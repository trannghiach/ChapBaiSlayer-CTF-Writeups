# v1tCTF 2025
## Category: Misc

### Exploitation
- Challenge cung cấp 1 file image (.jpeg). Tiến hành phân tích nó:
```
file MOOOO.jpeg
MOOOO.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "OOOMoOMoOMoOMoOMoOMoOMoOMoOMMMmoOMMMMMMmoOMMMMOOMOomOoMoOmoOmoomOo", baseline, precision 8, 270x148, components 3
```

```
exiftool MOOOO.jpeg
 ...
Comment: OOOMoOMoOMoOMoOMoOMoOMoOMoOMMMmoOMMMMMMmoOMMMMOOMOomOoMoOmoOmoomOo.MMM
...
```

- Nhận thấy, trong metadata của image chứa comment rất dài. 
- Sau khi tìm kiếm, xác định được đây là ngôn ngữ `COW` - một loại ngôn ngữ bí truyền (`esoteric programming language`)
- Loại bỏ các dấu `.` xuất hiện trong đoạn thông tin, và sử dụng tool [TIO](https://tio.run/#cow) để tiến hành phân tích

- Kết quả thu được:
```
thismaybeapasswordbutwhoreallyknowsimjustmessginitisapassword
```

- Đây là một mật khẩu. Điều này dẫn đến suy đoán rằng `MOOOO.jpeg` vẫn còn chứa thông tin. Trích xuất thông tin này:
```
steghide extract -sf MOOOO.jpeg         
Enter passphrase: [thismaybeapasswordbutwhoreallyknowsimjustmessginitisapassword]
wrote extracted data to "secret.zip".
```

- Extract file, thu được 2 file `.txt`, trong đó đáng chú ý là file `TRYYY.txt` với nội dung như sau:
```
TRY HARDERRR	      	 	     	    	      	 	   	 
       	 	    	  	      	  	  		    	      
	   	       	       	 	     	      	     		 
     	  	   	       	       	 	     	    	    	    
    	  	     	      	     	     	    	      	    
	  	       	       	 	     	    	   	    	  
      	    	    	    	    	  	  	       	    	     
       	       	    	      	    	     	    		    	       
    	  	     	  	      	     	   	 

```

- Đây rất có thể là 1 loại mã hóa `whitespace`. Decode bằng `stegsnow`, thu được flag

    ![alt text](image.png)

### Result
```
v1t{D0wn_Th3_St3gN0_R4bb1t_H0l3}
```