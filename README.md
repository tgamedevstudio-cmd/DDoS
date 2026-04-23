CÔNG CỤ KIỂM TRA TẤN CÔNG ĐA TẦNG
BỘ KIỂM THỬ BẢO MẬT CHUYÊN NGHIỆP
=====================================

THÔNG TIN SẢN PHẨM
-------------------
Tên: Công cụ kiểm tra tấn công đa tầng
Phiên bản: 4.0
Ngôn ngữ: C++ 17
Nền tảng: Windows x64 (Visual Studio 2022)
Loại: Kiểm thử bảo mật / Thâm nhập
Giấy phép: MIT

MÔ TẢ
------
Công cụ mô phỏng tấn công bảo mật chuyên nghiệp cho kiểm thử hệ thống. Hỗ trợ đầy đủ tấn công tầng 3, tầng 4 và tầng 7 với các tính năng nâng cao như giả mạo IP, xoay vòng proxy và kỹ thuật khuếch đại.

KIẾN TRÚC HỆ THỐNG
-------------------
Mô-đun 1: Tấn công tầng 3 (Tầng mạng)
Mô-đun 2: Tấn công tầng 4 (Tầng vận chuyển)
Mô-đun 3: Tấn công tầng 7 (Tầng ứng dụng)
Mô-đun 4: Công cụ giả mạo IP
Mô-đun 5: Thống kê và ghi nhật ký

TẤN CÔNG TẦNG 3 (Tầng mạng)
----------------------------
1. ICMP Flood (Ping Flood)
   - Loại: ICMP Echo Request
   - Mục tiêu: Thiết bị mạng, tường lửa
   - Phòng chống: Giới hạn tốc độ, lọc ICMP

2. UDP Flood
   - Loại: Tràn ngập UDP datagram
   - Mục tiêu: Máy chủ DNS, NTP, game
   - Phòng chống: Giới hạn tốc độ, lọc UDP

3. UDP Fragment Flood
   - Loại: Gói UDP phân mảnh
   - Mục tiêu: Hệ thống IDS/IPS tường lửa
   - Phòng chống: Giới hạn tái hợp mảnh

4. ICMP Fragment Flood
   - Loại: Gói ICMP phân mảnh
   - Mục tiêu: Bộ xử lý mạng
   - Phòng chống: Lọc gói phân mảnh

TẤN CÔNG TẦNG 4 (Tầng vận chuyển)
----------------------------------
1. SYN Flood
   - Loại: Kết nối nửa mở
   - Mục tiêu: Máy chủ web, tường lửa
   - Phòng chống: SYN cookie, tăng hàng đợi

2. ACK Flood
   - Loại: Gói ACK không có SYN
   - Mục tiêu: Tường lửa trạng thái
   - Phòng chống: Lọc trạng thái kết nối

3. RST Flood
   - Loại: Đặt lại kết nối giả mạo
   - Mục tiêu: Kết nối TCP đang hoạt động
   - Phòng chống: Xác thực gói RST

4. FIN Flood
   - Loại: Kết thúc kết nối giả
   - Mục tiêu: Kết nối TCP
   - Phòng chống: Xác thực tuần tự số

5. TCP Fragment Flood
   - Loại: Gói TCP phân mảnh
   - Mục tiêu: Ngăn xếp TCP
   - Phòng chống: Giới hạn tái hợp

6. TCP Connection Flood
   - Loại: Kết nối đầy đủ
   - Mục tiêu: Tài nguyên máy chủ
   - Phòng chống: Giới hạn kết nối

7. TCP Socket Stress
   - Loại: Giữ kết nối lâu
   - Mục tiêu: Hàng đợi kết nối
   - Phòng chống: Timeout kết nối

TẤN CÔNG TẦNG 7 (Tầng ứng dụng)
--------------------------------
1. HTTP Flood
   - Loại: Yêu cầu HTTP GET
   - Mục tiêu: Máy chủ web
   - Phòng chống: WAF, giới hạn tốc độ

2. HTTPS Flood
   - Loại: Kết nối SSL/TLS
   - Mục tiêu: Máy chủ web an toàn
   - Phòng chống: Giải mã SSL, WAF

3. Slowloris
   - Loại: Giữ kết nối mở
   - Mục tiêu: Máy chủ Apache, IIS
   - Phòng chống: Timeout yêu cầu

4. Slow Body
   - Loại: Gửi dữ liệu chậm
   - Mục tiêu: Ứng dụng web
   - Phòng chống: Giới hạn thời gian

5. POST Flood
   - Loại: Yêu cầu POST
   - Mục tiêu: Form đăng nhập, API
   - Phòng chống: Xác thực, CAPTCHA

6. DNS Amplification
   - Loại: Tấn công khuếch đại UDP
   - Hệ số: Lên đến 100x
   - Phòng chống: Lọc máy chủ mở

7. NTP Amplification
   - Loại: Tấn công monlist
   - Hệ số: Lên đến 500x
   - Phòng chống: Tắt monlist

8. Chargen Amplification
   - Loại: Chargen protocol
   - Hệ số: Lên đến 200x
   - Phòng chống: Tắt dịch vụ

9. SSDP Amplification
   - Loại: UPnP discovery
   - Hệ số: Lên đến 50x
   - Phòng chống: Tắt UPnP

TÍNH NĂNG NÂNG CAO
-------------------
1. Giả mạo IP
   - IP tĩnh tùy chỉnh
   - IP ngẫu nhiên tự động
   - Che giấu nguồn gốc thực

2. Xoay vòng Proxy
   - Tải proxy từ nhiều nguồn
   - Kiểm tra proxy hoạt động
   - Tự động chuyển đổi

3. Tối ưu hiệu suất
   - Đa luồng (lên đến 200)
   - Gói tin kích thước ngẫu nhiên
   - Độ trễ có cấu hình

4. Ghi nhật ký
   - Thời gian thực
   - Thống kê chi tiết
   - Lưu trữ lịch sử

YÊU CẦU HỆ THỐNG
------------------
- Hệ điều hành: Windows 10/11
- Visual Studio 2022
- Quyền Administrator (cho RAW socket)
- RAM: 256MB+
- CPU: 1.0GHz+

CÀI ĐẶT
--------
1. Mở Visual Studio 2022
2. Tạo Console App (C++)
3. Copy toàn bộ mã nguồn vào file .cpp
4. Project -> Properties -> Linker -> Input -> Additional Dependencies
5. Thêm: ws2_32.lib iphlpapi.lib
6. Build -> Build Solution
7. Chạy với quyền Administrator

CÁCH SỬ DỤNG
-------------
Cú pháp:
  tool.exe -t <đích> -m <phương thức> [tùy chọn]

Tùy chọn:
  -t <đích>        IP hoặc tên miền
  -m <phương thức>  Phương thức tấn công
  -p <cổng>        Cổng đích (mặc định 80)
  -d <giây>        Thời gian (mặc định 10)
  -c <luồng>       Số luồng (mặc định 1)
  --path <đường>   Đường dẫn HTTP
  --spoof <IP>     Giả mạo IP nguồn
  --random-spoof   IP nguồn ngẫu nhiên

VÍ DỤ
------
1. ICMP Flood:
   tool.exe -t 192.168.1.1 -m icmp -d 30 -c 4

2. SYN Flood với IP giả:
   tool.exe -t 10.0.0.1 -m syn -p 80 -d 60 -c 100 --random-spoof

3. Slowloris bảo mật:
   tool.exe -t example.com -m slowloris -p 80 -d 120 -c 500

4. HTTP Flood:
   tool.exe -t example.com -m http -p 80 -d 60 -c 10

5. DNS khuếch đại:
   tool.exe -t 8.8.8.8 -m dns -p 53 -d 30 -c 4

6. UDP Flood:
   tool.exe -t 192.168.1.1 -m udp -p 53 -d 30 -c 4

7. Kết hợp giả IP:
   tool.exe -t target.com -m syn -p 80 -d 30 --spoof 1.2.3.4

8. NTP khuếch đại:
   tool.exe -t 192.168.1.1 -m ntp -p 123 -d 30

9. POST Flood:
   tool.exe -t api.example.com -m post -p 443 -d 30 -c 10

10. RST Flood:
    tool.exe -t 10.0.0.1 -m rst -p 80 -d 30 -c 50

DANH SÁCH PHƯƠNG THỨC ĐẦY ĐỦ
----------------------------
Tầng 3:
  icmp      - ICMP echo request flood
  udp       - UDP datagram flood
  udpfrag   - UDP fragment flood

Tầng 4:
  syn       - SYN flood
  ack       - ACK flood
  rst       - RST flood
  fin       - FIN flood
  tcpfrag   - TCP fragment flood
  tcpconn   - TCP connection flood
  tcpstress - TCP socket stress

Tầng 7:
  http      - HTTP GET flood
  https     - HTTPS flood
  slowloris - Slowloris attack
  slowbody  - Slow body attack
  post      - POST flood
  dns       - DNS amplification
  ntp       - NTP amplification
  chargen   - Chargen amplification
  ssdp      - SSDP amplification

ĐỌC KẾT QUẢ
------------
[*] - Thông tin
[+] - Thành công
[-] - Lỗi
[!] - Cảnh báo

Thống kê hiển thị:
  [10s] Pkt:10000 | MB:15 | Mbps:12.5 | Conn:500 | Rate:1000/s

SỰ CỐ VÀ GIẢI PHÁP
-------------------
1. "ICMP/SYN flood requires admin privileges"
   - Chạy chương trình với quyền Administrator
   - Click chuột phải -> Run as Administrator

2. "Cannot resolve host"
   - Kiểm tra kết nối mạng
   - Kiểm tra tên miền hoặc IP
   - Dùng IP trực tiếp thay vì tên miền

3. "Winsock failed"
   - Kiểm tra cài đặt mạng Windows
   - Khởi động lại máy
   - Kiểm tra file hệ thống

4. Không có kết nối
   - Kiểm tra tường lửa
   - Thử tắt tường lửa tạm thời
   - Kiểm tra antivirus

GIỚI HẠN
---------
1. Yêu cầu quyền Administrator
2. RAW socket chỉ hoạt động trên Windows
3. Giả mạo IP không hoạt động qua proxy
4. HTTPS không có SSL handshake đầy đủ
5. Tốc độ phụ thuộc vào mạng

PHÒNG CHỐNG
------------
1. Tường lửa: Giới hạn tốc độ, lọc gói
2. Hệ thống IDS/IPS: Phát hiện bất thường
3. WAF: Chặn tầng ứng dụng
4. CDN: Hấp thụ lưu lượng
5. Rate limiting: Ngăn quá tải
6. SYN cookie: Chống SYN flood

BẢO MẬT
--------
Công cụ chỉ dùng cho kiểm thử bảo mật trên hệ thống được ủy quyền.
Vi phạm pháp luật về an ninh mạng sẽ bị xử lý.
