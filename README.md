# Unicorn Engine Talk

Code, Target Firmware, and Slides for _Unicorn Engine - What, Why, How._

The talk was delivered at the July 2023 edition of hack::soho and the recording is available on IOActive's YouTube channel: https://youtu.be/deEUF6dkdws

### Usage
Execute the following commands to emulate the target firmware discussed in the talk:

```
git clone https://github.com/nicoloboatto/unicorn-engine-talk.git
cd unicorn-engine-talk
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 emulate_target_firmware.py
```