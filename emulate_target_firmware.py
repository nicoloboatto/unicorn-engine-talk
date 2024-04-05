# Copyright (c) 2023 Nicolò Boatto
# This code is licensed under MIT license (see LICENSE for details).

import hexdump
from unicorn import *
from unicorn.arm_const import *
import sys
import hashlib
from Crypto.Cipher import AES
from io import BufferedReader
import lief

# Set up memory regions and addresses
# In this case it's an ELF but it might be necessary to set up sections separately.
ELF_BASE            = 0x8000000

STACK_BASE          = 0x3000000
STACK_SIZE          = 0x2000

HEAP_BASE           = 0x9000000
HEAP_SIZE           = 0x100000
heap_pointer        = HEAP_BASE

# Some useful constants, actually just one.

BLOCK_SIZE          = 1024 * 4

# Variables for tracing support

trace               = 0
full_trace          = 0
trace_file          = 0
last_function       = ""

# ELF Parser and Symbols

lief_binary = []
symbol_table = []

# Key and iv we've decoded

key = ""
iv  = ""


def init_emulation(elf: BufferedReader):
    global lief_binary

    mu = Uc(UC_ARCH_ARM, UC_MODE_MCLASS)
    
    # Set thumb mode in the CPSR
    mu.reg_write(UC_ARM_REG_CPSR, 0x20)

    # Map normal working regions
    mu.mem_map(STACK_BASE, STACK_SIZE)
    mu.mem_map(HEAP_BASE, HEAP_SIZE)

    initial_sp = STACK_BASE + STACK_SIZE
    mu.reg_write(UC_ARM_REG_SP, initial_sp)

    lief_binary = lief.parse(elf)

    build_symbol_table(lief_binary)

    # Offsets of the the .isr_vector, .text, and .rodata sections of the elf
    isr_vector = lief_binary.get_section(".isr_vector")
    ISR_OFFSET      = isr_vector.file_offset
    ISR_SIZE        = isr_vector.size
    ISR_ADDRESS     = isr_vector.virtual_address
    
    text = lief_binary.get_section(".text")
    TEXT_OFFSET     = text.file_offset
    TEXT_SIZE       = text.size
    TEXT_ADDRESS    = text.virtual_address

    rodata = lief_binary.get_section(".rodata")
    RODATA_OFFSET   = rodata.file_offset
    RODATA_SIZE     = rodata.size
    RODATA_ADDRESS  = rodata.virtual_address

    TOTAL_SIZE = RODATA_OFFSET + RODATA_SIZE - ISR_OFFSET

    # Map a single memory block that allows us to get around the Unicorn engine mapping limitations
    mu.mem_map(ELF_BASE, resize_to_block(TOTAL_SIZE, BLOCK_SIZE))
    
    elf.seek(ISR_OFFSET)
    mu.mem_write(ISR_ADDRESS, elf.read(ISR_SIZE))

    elf.seek(TEXT_OFFSET)
    mu.mem_write(TEXT_ADDRESS, elf.read(TEXT_SIZE))

    elf.seek(RODATA_OFFSET)
    mu.mem_write(RODATA_ADDRESS, elf.read(RODATA_SIZE))

    return mu


# Makes an array of symbols ordered by address so function names
#   can be looked up at any address inside a function
def build_symbol_table(elf):
    global symbol_table
    print("Building Symbol Table...")

    for symbol in elf.static_symbols:
        if symbol.is_function:
            symbol_table.append({"name": symbol.name, "sym_address": symbol.value})
    symbol_table.sort(key= lambda s: s["sym_address"])

def resize_to_block(value, block):
    return value + (block - (value % block))

def print_env(mu : unicorn.Uc):

    print_regs(mu)
    print_stack(mu)

    if mu.reg_read(UC_ARM_REG_PC) != 0:
        print("Next instructions:")
        hexdump.hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_PC), 0x20))

def print_regs(mu : unicorn.Uc):
    print("SP = 0x%x" % mu.reg_read(UC_ARM_REG_SP))
    print("PC = 0x%x" % mu.reg_read(UC_ARM_REG_PC))
    print("R0 = 0x%x" % mu.reg_read(UC_ARM_REG_R0))
    print("R1 = 0x%x" % mu.reg_read(UC_ARM_REG_R1))
    print("R2 = 0x%x" % mu.reg_read(UC_ARM_REG_R2))
    print("R3 = 0x%x" % mu.reg_read(UC_ARM_REG_R3))
    print("R4 = 0x%x" % mu.reg_read(UC_ARM_REG_R4))

def print_stack(mu : unicorn.Uc):
    print("Contents of stack:")
    AMOUNT = 0x300
    hexdump.hexdump(mu.mem_read(STACK_BASE + STACK_SIZE - AMOUNT, AMOUNT))


def hook_code(mu : unicorn.Uc, address, size, data):
    global last_function
    global trace
    global full_trace
    global lief_binary
    global symbol_table
    function_name = get_function_name(address, symbol_table)

    # Print function name and register values each time a new function is called
    if ((function_name != last_function) and trace == 1 ) or full_trace == 1: 
        print(">>> Tracing instruction at 0x%x, in function %s" % (address, function_name))
        print_regs(mu)  
    last_function = function_name
    
    # FUNCTION SUBSTITUTION   
    # Substitute my own implementation of malloc to be able to run in a limited environment
    if address == lief_binary.get_symbol("malloc").value + 1:
        malloc(mu)
    # Substitute my own implementation of SHA256 to skip the emulated one
    elif address == lief_binary.get_symbol("mbedtls_sha256").value + 1:
        SHA256(mu)
    # Substitute my own implementation of setkey to skip the emulated one and intercept the key
    elif address == lief_binary.get_symbol("mbedtls_aes_setkey_dec").value + 1:
        mbed_setkey(mu)
    # Substitute my own implementation of setkey to skip the emulated one and intercept the iv
    elif address == lief_binary.get_symbol("mbedtls_aes_crypt_cbc").value + 1:
        mbed_aes_crypt(mu)


def print_next_instruction_bytes(mu : unicorn.Uc):
    print("INVALID INSTRUCTION!")
    address = mu.reg_read(UC_ARM_REG_PC)
    print("Next instruction bytes are: %x" % int.from_bytes(mu.mem_read(address, 4), byteorder="big"))


# Substitute SHA256 function, which just uses the python version
# The original implementation caused issues and crashed the emulation
def SHA256(mu : unicorn.Uc):
    input_address  = mu.reg_read(UC_ARM_REG_R0)
    input_length   = mu.reg_read(UC_ARM_REG_R1)
    input = mu.mem_read(input_address, input_length)
    hash = hashlib.sha256(input).digest()
    print("SHA256 Input:  %s" % input.decode("utf8"))
    print("SHA256 Output: %s" % bytes(hash).hex())

    output_address = mu.reg_read(UC_ARM_REG_R2)
    mu.mem_write(output_address, hash)

    # Return to the end of the SHA256 function
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))

# Substitute the setkey function with one that just prints the key
def mbed_setkey(mu: unicorn.Uc):
    global key

    key_address = mu.reg_read(UC_ARM_REG_R1)
    key = mu.mem_read(key_address, 32)
    print("Key = %s" % key.hex())
    # Return to the end of the setkey function
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))

# Substitute the crypt function with one that just prints the iv
def mbed_aes_crypt(mu: unicorn.Uc):
    global iv

    iv_address = mu.reg_read(UC_ARM_REG_R3)
    iv = mu.mem_read(iv_address, 16)
    print("IV = %s" % iv.hex())
    # Return to the end of the crypt function
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))

# My own malloc implementation, which just stores things sequentially 
def malloc(mu : unicorn.Uc):
    global heap_pointer

    size = mu.reg_read(UC_ARM_REG_R0)
    address = internal_malloc(mu, size)
    mu.reg_write(UC_ARM_REG_R0, address)
    
    # Restore execution to the end of the malloc function
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
    

def internal_malloc(mu: unicorn.Uc, size):
    global heap_pointer

    address = heap_pointer
    print("Malloc called with size: 0x%x" % size)
    heap_pointer = heap_pointer + size
    return address

def get_function_name(address, symbol_table):
    for i, symbol in enumerate(symbol_table):
        if symbol["sym_address"] -1 > address:
            return symbol_table[i-1]["name"]

def decrypt(enc):
    global key
    global iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(enc).decode('utf-8')

def main():
    if trace_file:
        sys.stdout = open('./trace.txt','w')
    with open("./target_firmware.elf", "rb") as elf:

        # Address of the decrypt_firmware function that we're attacking
        decrypt_firmware = 0x8000585

        # Set the emulation start address as decrypt_firmware
        #   and end once we have what we need.
        emu_start = decrypt_firmware
        emu_end = 0x80005f4

        print("Initialising Emulator...")
        mu = init_emulation(elf)

        # Write the "firmware" into the heap
        firmware = bytes.fromhex("2d685cbae23ae7f71b97df2cb21d955f")
        firmware_size = len(firmware)
        firmware_address = internal_malloc(mu, firmware_size)
        mu.mem_write(firmware_address, firmware)
        
        # Set up register state for decrypt_firmware
        mu.reg_write(UC_ARM_REG_R0, firmware_address)
        mu.reg_write(UC_ARM_REG_R1, firmware_size)
        mu.reg_write(UC_ARM_REG_R2, 0)
        mu.reg_write(UC_ARM_REG_R3, 0)
   
        try:
            # Starting emulation
            mu.reg_write(UC_ARM_REG_PC, emu_start)
            mu.hook_add(UC_HOOK_CODE, hook_code)
            print("Emulation started.")
            mu.emu_start(emu_start, emu_end)
            print("Emulation ended, decrypting secret...")
            print("The secret is: %s" % decrypt(firmware))
            
        except UcError as e:
            print("Error: %s" % e)
            print_next_instruction_bytes(mu)
            print_env(mu)

if __name__ == "__main__" :
    main()