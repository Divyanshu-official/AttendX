# AttendX

> Wi-Fi Hotspot-Based Attendance Management System with local network verification.

AttendX is a web-based attendance management system designed for classroom environments. It allows a teacher to control student registration and attendance while verifying that students are connected to the teacher's classroom hotspot.

## 🌐 Live Demo

**Public Website:**  
https://attendx-public-dev.vercel.app/

**GitHub Repository:**  
https://github.com/Divyanshu-official/AttendX

> The public website is the student-facing interface. Attendance verification requires the student's device to be connected to the teacher's hotspot and the teacher's local Flask verifier to be running.

## ✨ Features

- Teacher login and protected Teacher Panel
- Student registration
- Attendance marking
- Local classroom-network verification
- Wi-Fi hotspot-based attendance validation
- Shareable student access link
- Copy Link functionality
- Duplicate attendance prevention
- Teacher-controlled Registration ON/OFF
- Teacher-controlled Attendance ON/OFF
- Registered student management
- Attendance records
- HMAC-SHA256 based local verification
- Signed verification tokens
- Public HTTPS student-facing website
- Responsive interface

## 🧠 How AttendX Works

AttendX uses a hybrid public + local architecture.

```text
                    Teacher
                       │
                       ▼
              Teacher Mobile Hotspot
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
       Teacher Laptop       Student Phone
       Flask Server              │
              │                  │
              │                  ▼
              │          Public AttendX URL
              │                  │
              │                  ▼
              └──────► Local Verification
                              │
                              ▼
                    Registration / Attendance