# HackTheBoo 2025 - The Gate of Broken Names
## Category: Web


### Exploitation
- Trong `init-data.js`:
    - Hàm đọc flag:
    ```javascript
    function readFlag() {
      try {
        if (fs.existsSync("/flag.txt")) {
          return fs.readFileSync("/flag.txt", 'utf8').trim();
        }
        return 'HTB{FAKE_FLAG_FOR_TESTING}';
      } catch (error) {
        console.error('Error reading flag:', error);
        return 'HTB{FAKE_FLAG_FOR_TESTING}';
      }
    }
    ```

    - Note chứa Flag được random id và set private, các note còn lại cũng được sinh ra để gây nhiễu
    ```javascript
    export function generateRandomNotes(totalNotes = 200) {
      const flag = readFlag();
      const flagPosition = Math.floor(Math.random() * totalNotes) + 1;

      console.log(`🎃 Generating ${totalNotes} notes...`);

      const noteTypes = [
        'Gate Inspection Log',
        'Security Audit Report',

          ...

      ];

      const contentTemplates = [
        'Completed routine inspection. All gates functioning within normal parameters. Minor adjustments made to threshold calibration.',
        'Security audit completed successfully. No vulnerabilities detected in current configuration. Recommend quarterly reviews.',

          ...

      ];

      const notes = [];

      for (let i = 1; i <= totalNotes; i++) {
        if (i === flagPosition) {
          notes.push({
            id: 10 + i,
            user_id: 1,
            title: 'Critical System Configuration',
            content: flag,
            is_private: 1,
            created_at: new Date(Date.now() - Math.floor(Math.random() * 30 + 1) * 24 * 60 * 60 * 1000).toISOString(),
            updated_at: new Date(Date.now() - Math.floor(Math.random() * 30 + 1) * 24 * 60 * 60 * 1000).toISOString()
          });
        } else {
          const noteType = noteTypes[Math.floor(Math.random() * noteTypes.length)];
          const content = contentTemplates[Math.floor(Math.random() * contentTemplates.length)];
          const userId = Math.floor(Math.random() * 3) + 1; // Only users 1, 2, 3 (admin, mira, keeper)
          const isPrivate = Math.floor(Math.random() * 2);
          const daysAgo = Math.floor(Math.random() * 365) + 1;

          notes.push({
            id: 10 + i,
            user_id: userId,
            title: noteType,
            content: content,
            is_private: isPrivate,
            created_at: new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000).toISOString(),
            updated_at: new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000).toISOString()
          });
        }
      }

      return notes;
    }
    ```

- Hàm `generateRandomNotes()` được gọi trong `data.js`:
```javascript
 const randomNotes = generateRandomNotes(200);
```

- Như vậy, ta cần tìm cách đọc được các note private trước

- Mặt khác, trang web lại không kiểm tra private của id trước khi trả về thông tin -> Chỉ cần gọi tới id thì sẽ có được thông tin của note tương ứng (Không quan tâm đến private hay không) - IDOR
```java
router.get('/:id', async (req, res) => {
  if (!req.session.user_id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const noteId = parseInt(req.params.id);

  try {
    const note = db.notes.findById(noteId);

    if (note) {
      const user = getUserById(note.user_id);
      res.json({
        ...note,
        username: user ? user.username : 'Unknown'
      });
    } else {
      res.status(404).json({ error: 'Note not found' });
    }
  } catch (error) {
    console.error('Error fetching note:', error);
    res.status(500).json({ error: 'Failed to fetch note' });
  }
});
```

![alt text](./images/image-1.png)


- C1: Brute force (Burp Intruder)
![alt text](./images/image-2.png)


- C2: Script
**<i>Updating...</i>**

### Result
```
HTB{br0k3n_n4m3s_r3v3rs3d_4nd_r3st0r3d_7388e195ba41b52ddf1ee90962a18cac}
```