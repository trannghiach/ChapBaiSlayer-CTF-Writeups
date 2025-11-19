# **Uwa so Piano**

Category: Misc

Author: l34ngyn

In this challenge, we unzip a tar archive and get a file named `megalovania_snippet.mid`.

## What is a MIDI File?

A MIDI file (.mid) is a Musical Instrument Digital Interface file that contains musical information in digital format. Unlike audio files like MP3 or WAV, MIDI files don't store actual sound recordings. Instead, they store instructions about how music should be played, including notes, timing, pitch, velocity, and instrument information.

## How to read this file?

```bash
pip install mido
```

```python
import mido

def midi_to_text(input_mid_file, output_txt_file):
    mid = mido.MidiFile(input_mid_file)
    with open(output_txt_file, 'w', encoding='utf-8') as f:
        
        for i, track in enumerate(mid.tracks):
            f.write(f'Track {i}: {track.name}\n')
            for msg in track:
                f.write(str(msg) + '\n')

if __name__ == "__main__":
    input_file = 'megalovania_snippet.mid'
    output_file = 'result.txt'
    midi_to_text(input_file, output_file)
```

After running the code above, we get a file named `result.txt` with content like below:

```bash
Track:
program_change channel=1 program=32 time=0
note_on channel=1 note=38 velocity=97 time=0
note_off channel=1 note=38 velocity=64 time=480
note_on channel=1 note=50 velocity=109 time=0
note_off channel=1 note=50 velocity=64 time=480
note_on channel=1 note=38 velocity=97 time=0
note_off channel=1 note=38 velocity=64 time=480
note_on channel=1 note=50 velocity=116 time=0
note_off channel=1 note=50 velocity=64 time=480
note_on channel=1 note=38 velocity=101 time=0
note_off channel=1 note=38 velocity=64 time=480
note_on channel=1 note=50 velocity=117 time=0
note_off channel=1 note=50 velocity=64 time=480
note_on channel=1 note=38 velocity=114 time=0
...
MetaMessage('end_of_track', time=0)
```

## So, what happens?

Please focus on the `note_on` lines; the value of `velocity` is exactly ASCII values, so we use the code below to convert these values to ASCII characters.

```python
import re

with open('result.txt', 'r') as file:
    data = file.readlines()

flags = []

for line in data:
    if "velocity" in line and "note_on" in line:
        velocity_match = re.search(r'velocity=(\d+)', line)
        if velocity_match:
            velocity_value = int(velocity_match.group(1))
            flags.append(chr(velocity_value))

print(''.join(flags))
```

Now, we get the flag: `amateursCTF{h1t_th3_n0t3s}`
