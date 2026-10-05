import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { parseAndAnalyzeApk } from './analyzer.js';

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 150 * 1024 * 1024 } // 150MB upload cap
});

app.post('/api/scan', upload.single('apkFile'), async (req, res) => {
  try {
    // Validate upload existence
    if (!req.file) {
      return res.status(400).json({ error: 'No APK file uploaded.' });
    }

    // Execute the analysis engine on the file buffer
    const report = await parseAndAnalyzeApk(req.file.buffer);
    
    // Append user-facing metadata
    report.fileName = req.file.originalname;
    report.fileSize = (req.file.size / (1024 * 1024)).toFixed(2) + ' MB';

    return res.json(report);
  } catch (error) {
    console.error('Scan Error:', error);
    return res.status(500).json({ 
      error: 'Failed to analyze APK. Ensure it is a valid, uncorrupted Android package.' 
    });
  }
});

app.listen(PORT, () => {
  console.log(`🛡️ Threat Analyzer Backend active at http://localhost:${PORT}`);
});