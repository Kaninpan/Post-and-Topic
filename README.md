## (PHP Hardcode) โปรเจ็คนี้เป็นโปรเจค ๆ เล็ก ๆ ให้ความคล้ายเหมือน Facebook (META) ในส่วนของ Design ระบบง่าย ๆ ที่คิดอยากจะทำก็ทำครับ 🤣

>[!NOTE]
>**Version code PHP 8.x เพื่อความปลอดภัยและมีประสิทธิ์ภาพมากยิ่งขึ้น**
<hr></hr>

>[!TIP]
> ### ผู้ใช้งานสามารถทำอะไรได้บ้าง ? 
> - ผู้ใช้งานสามารถดำเนินการสร้างโพสข้อความพร้อมแนบรูปหรือ VDO ได้<br>
> - ผู้ใช้งานสามารถแก้ไข / ลบ ได้ก็ต่อเมื่อ **<ins>Username</ins>** หรือถ้า ตรงกับ **<ins>IP</ins>** ที่บันทึกไว้<br>
> - ปุ่ม **<ins>Reaction</ins>** ให้อารมณ์เหมือนกดสถานะใน Facebook (META)<br>
> - อัปโหลดรูปโปรไฟล์ พร้อมลบไฟล์เก่าเมื่อมีการอัพเดท<br>
> - UI ที่ทำมาแบบหน้าเดียว มี **<ins>Emoji picker modal</ins>**<br>
> - การเก็บข้อมูลที่ใช้เป้น **<ins>data.json (JSON)</ins>** ไม่ใช้ฐานข้อมูล<br>
> - และ **<ins>API (POST and GET)</ins>** ต่าง ๆ **<ins>(ADD,delete,reaction,comment,edit,)</ins>**<br>

<hr></hr>

>[!IMPORTANT]
> ### มีความปลอดภายในเรื่องของ 
> - CSRF Protection
> - Session_regenerate_id
> - htmlspecialchars
> - File-upload Validation
> - Rate limiting
> - Authorization checks
> - Atomic write
> - IP handling
