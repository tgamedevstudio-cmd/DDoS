#!/usr/bin/env python3
import struct
import os
import time

def pad(data, size):
    return data + b'\x00' * (size - len(data))

def make_iso(output_path, files):
    SECTOR = 2048
    file_start_sector = 19
    file_sectors = []
    offset = file_start_sector
    
    for name, content in files:
        file_sectors.append(offset)
        sectors_needed = (len(content) + SECTOR - 1) // SECTOR
        offset += sectors_needed
    
    total_sectors = offset

    def lsb_msb_16(n):
        return struct.pack('<H', n) + struct.pack('>H', n)
    
    def lsb_msb_32(n):
        return struct.pack('<I', n) + struct.pack('>I', n)
    
    def date_field(t=None):
        if t is None:
            t = time.gmtime()
        return bytes([
            t.tm_year - 1900, t.tm_mon, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec, 0
        ])
    
    def dir_record(name_bytes, sector, size, is_dir=False):
        flags = 0x02 if is_dir else 0x00
        name_len = len(name_bytes)
        record_len = 33 + name_len
        if record_len % 2 != 0:
            record_len += 1
        
        rec = bytes([record_len, 0])
        rec += lsb_msb_32(sector)
        rec += lsb_msb_32(size)
        rec += date_field()
        rec += bytes([flags, 0, 0, 0, 0])
        rec += lsb_msb_16(1)
        rec += bytes([name_len])
        rec += name_bytes
        
        if len(rec) % 2 != 0:
            rec += b'\x00'
        
        return rec

    root_dir = b''
    root_dir += dir_record(b'\x00', 18, SECTOR, is_dir=True)
    root_dir += dir_record(b'\x01', 18, SECTOR, is_dir=True)
    
    for i, (name, content) in enumerate(files):
        root_dir += dir_record(name.encode(), file_sectors[i], len(content))
    
    root_dir_padded = pad(root_dir, SECTOR)

    pvd = b'\x01'
    pvd += b'CD001\x01\x00'
    pvd += b'\x00' * 32
    pvd += pad(b'KALI_CLOUD', 32)
    pvd += b'\x00' * 8
    pvd += lsb_msb_32(total_sectors)
    pvd += b'\x00' * 32
    pvd += lsb_msb_16(1)
    pvd += lsb_msb_16(1)
    pvd += lsb_msb_16(SECTOR)
    pvd += lsb_msb_32(total_sectors * SECTOR)
    pvd += struct.pack('<I', 18)
    pvd += struct.pack('<I', 0)
    pvd += struct.pack('>I', 18)
    pvd += struct.pack('>I', 0)
    pvd += dir_record(b'\x00', 18, SECTOR, is_dir=True)
    pvd += b' ' * 128
    pvd += b' ' * 128
    pvd += b' ' * 128
    pvd += b' ' * 128
    pvd += b' ' * 37
    pvd += b' ' * 37
    pvd += b' ' * 37
    pvd += b'2025010100000000\x00'
    pvd += b'2025010100000000\x00'
    pvd += b'2025010100000000\x00'
    pvd += b'2025010100000000\x00'
    pvd += b'\x01\x00'
    
    pvd = pad(pvd, SECTOR)
    term = pad(b'\xff' + b'CD001\x01', SECTOR)

    with open(output_path, 'wb') as f:
        f.write(b'\x00' * (16 * SECTOR))
        f.write(pvd)
        f.write(term)
        f.write(root_dir_padded)
        for name, content in files:
            sectors_needed = (len(content) + SECTOR - 1) // SECTOR
            f.write(pad(content, sectors_needed * SECTOR))
    
    print(f"Đã tạo ISO thành công: {output_path} ({os.path.getsize(output_path)} bytes)")

# Meta-data cho VPS Kali
meta_data = """instance-id: kali-vps-2026
local-hostname: kali-vps
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
""".encode('utf-8')

# User-data cho Kali Linux
user_data = """#cloud-config
# Cấu hình cho Kali Linux VPS

# Người dùng
users:
  - name: kali
    gecos: Kali Linux User
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    groups: users, sudo, admin
  - name: root
    lock_passwd: false

# Mật khẩu
chpasswd:
  expire: false
  list:
    - kali:kali2026
    - root:kali2026

# SSH
ssh_pwauth: true
disable_root: false

# Cập nhật
package_update: true
package_upgrade: true

# Kho Kali
apt:
  sources:
    kali.list:
      source: "deb https://http.kali.org/kali kali-rolling main non-free contrib"
      keyid: ED444FF07D8D0BF6

# Danh sách phần mềm
packages:
  - kali-linux-headless
  - kali-linux-default
  - nmap
  - masscan
  - wireshark
  - tcpdump
  - metasploit-framework
  - john
  - hashcat
  - hydra
  - sqlmap
  - gobuster
  - ffuf
  - wpscan
  - nikto
  - burpsuite
  - zaproxy
  - aircrack-ng
  - bettercap
  - docker.io
  - docker-compose
  - python3
  - python3-pip
  - git
  - vim
  - htop
  - tmux
  - openssh-server
  - curl
  - wget

# Ghi file cấu hình
write_files:
  - path: /etc/systemd/system/kali-setup.service
    content: |
      [Unit]
      Description=Kali Linux Setup Service
      After=network.target
      
      [Service]
      Type=oneshot
      ExecStart=/usr/local/bin/kali-setup.sh
      
      [Install]
      WantedBy=multi-user.target
      
  - path: /usr/local/bin/kali-setup.sh
    content: |
      #!/bin/bash
      echo "Đang cài đặt Kali Linux..."
      apt update
      apt full-upgrade -y
      systemctl enable postgresql
      systemctl start postgresql
      msfdb init
      searchsploit -u
      mkdir -p /usr/share/wordlists
      cd /usr/share/wordlists
      git clone https://github.com/danielmiessler/SecLists.git
      systemctl enable docker
      systemctl start docker
      echo "Cài đặt hoàn tất!"
    permissions: '0755'

# Các lệnh chạy
runcmd:
  - systemctl enable ssh
  - systemctl start ssh
  - systemctl enable postgresql
  - systemctl start postgresql
  - systemctl enable kali-setup.service
  - chmod +x /usr/local/bin/kali-setup.sh

# Khởi động lại
power_state:
  mode: reboot
  timeout: 30
  condition: True
""".encode('utf-8')

if __name__ == "__main__":
    # Tạo thư mục
    vps_dir = os.path.join(os.environ['HOME'], 'vps-kali')
    os.makedirs(vps_dir, exist_ok=True)
    
    # Đường dẫn output
    output_iso = os.path.join(vps_dir, 'kali-cloud-init.iso')
    
    # Tạo ISO
    make_iso(output_iso, [
        ('meta-data', meta_data),
        ('user-data', user_data),
    ])
    
    print("\n" + "="*60)
    print("ĐÃ TẠO ISO THÀNH CÔNG")
    print("Đường dẫn: " + output_iso)
    print("="*60)
    
    print("\nCÁCH SỬ DỤNG:")
    print("-"*60)
    print("""
1. Tạo disk image:
   qemu-img create -f qcow2 kali-vps.qcow2 40G

2. Chạy VM:
   qemu-system-x86_64 \\
     -drive file=kali-vps.qcow2,format=qcow2 \\
     -cdrom ~/vps-kali/kali-cloud-init.iso \\
     -m 4096 \\
     -smp 2 \\
     -net user,hostfwd=tcp::2222-:22 \\
     -net nic

3. Kết nối SSH:
   ssh kali@localhost -p 2222
   Mật khẩu: kali2026

4. Kết nối VNC (nếu cần):
   qemu-system-x86_64 ... -vnc :1
   vncviewer localhost:5901
    """)
    
    print("\nCÔNG CỤ ĐÃ ĐƯỢC CÀI ĐẶT:")
    print("-"*60)
    cong_cu = [
        "Metasploit Framework - Khung tấn công",
        "Nmap - Quét mạng",
        "Wireshark - Phân tích gói tin",
        "John the Ripper - Bẻ khóa mật khẩu",
        "Hashcat - Bẻ khóa hash",
        "Hydra - Tấn công brute force",
        "SQLmap - Tấn công SQL injection",
        "Gobuster - Dò đường dẫn web",
        "WPScan - Quét WordPress",
        "Nikto - Quét lỗ hổng web",
        "Aircrack-ng - Tấn công WiFi",
        "Bettercap - Tấn công MITM",
        "Docker - Container hóa"
    ]
    for i, tool in enumerate(cong_cu, 1):
        print(f"  {i:2}. {tool}")
    
    print("\nTHÔNG TIN KHÁC:")
    print("-"*60)
    print(f"  Thư mục chứa ISO: {vps_dir}")
    print(f"  Dung lượng ISO: {os.path.getsize(output_iso) / 1024 / 1024:.2f} MB")
    print("="*60)
