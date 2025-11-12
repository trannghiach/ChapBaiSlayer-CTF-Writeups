@l34ngyn

<img width="854" height="412" alt="image" src="https://github.com/user-attachments/assets/03e5b4d0-de10-4297-99d8-1334f9bc8016" />


First, we receive a DOCX file that hides sensitive data, so we try using `binwalk` to see what hiding inside.

<img width="1899" height="490" alt="image" src="https://github.com/user-attachments/assets/55ee8985-6059-4a7e-8160-35e606de8e10" />


It seems the file extension has been changed, try changing it to .zip and unzip it. Now, we have a folder called OSU_Ethics_Report.

<img width="1760" height="843" alt="image" src="https://github.com/user-attachments/assets/7266cc89-7d94-4555-98f5-50adc7990182" />

I think the flag is in one of the files in this folder, so try using `grep` to find it.

Command:
```
grep -rl "string" /path/to/folder
```

<img width="868" height="276" alt="image" src="https://github.com/user-attachments/assets/cb0dc7df-0454-4c63-8913-e5a16ede2659" />


Finally, after running the above command, we also use the `grep` command to get the flag of this challenge.

Flag:
```
bctf{docx_is_zip}
```
