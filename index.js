require('dotenv').config();
const express = require('express');
const axios = require('axios');
const qs = require('querystring');
const crypto = require('crypto');
const SecureTokenStorage = require('./tokenStorage');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT;
const SIX_HOURS = 6 * 60 * 60 * 1000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize secure storage with encryption key from environment
const tokenStorage = new SecureTokenStorage(process.env.ENCRYPTION_KEY);

// Store code verifier for PKCE flow
let codeVerifier = null;

// Generate random string for code verifier (TikTok's official method)
function generateRandomString(length) {
  var result = '';
  var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

// Generate PKCE code verifier and challenge (TikTok's official method)
function generatePKCE() {
  // Generate random code verifier (43-128 characters as per TikTok docs)
  const verifier = generateRandomString(64); // Using 64 characters for good entropy
  
  // Generate code challenge using SHA256 with hex encoding (TikTok's method)
  const challenge = crypto.createHash('sha256').update(verifier).digest('hex');
  
  return { verifier, challenge };
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Root endpoint with basic info
app.get('/', (req, res) => {
  res.json({
    name: 'TikTok OAuth2 Server',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      auth: '/auth/login',
      callback: '/auth/callback',
      creator_info: '/creator-info',
      user_info: '/user/info',
      video_direct_post: '/video/direct-post',
      video_upload: '/video/upload',
      video_status: '/video/status?publish_id=YOUR_PUBLISH_ID',
      health: '/health',
      shutdown: 'POST /shutdown',
      force_shutdown: 'POST /shutdown/force',
      nuclear_shutdown: 'POST /shutdown/nuclear'
    }
  });
});

// 1. Redirect user to TikTok auth page with PKCE
app.get('/auth/login', (req, res) => {
  // Generate PKCE code verifier and challenge
  const pkce = generatePKCE();
  codeVerifier = pkce.verifier; // Store for later use in callback

  const params = {
    client_key: process.env.TIKTOK_CLIENT_KEY,
    redirect_uri: process.env.TIKTOK_REDIRECT_URI,
    response_type: 'code',
    scope: 'user.info.basic,user.info.profile,user.info.stats,video.publish,video.upload',
    state: 'secureRandomState123', // optional
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256'
  };

  const authUrl = `https://www.tiktok.com/v2/auth/authorize/?${qs.stringify(params)}`;
  res.redirect(authUrl);
});

// 2. Callback endpoint to handle TikTok redirect with PKCE
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code');
  
  if (!codeVerifier) return res.status(400).send('No code verifier found');

  //console.log('Callback received - Code:', code);
  //console.log('Stored code verifier:', codeVerifier);

  try {
    const requestData = new URLSearchParams({
      client_key: process.env.TIKTOK_CLIENT_KEY,
      client_secret: process.env.TIKTOK_CLIENT_SECRET,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: process.env.TIKTOK_REDIRECT_URI,
      code_verifier: codeVerifier
    });

    const tokenRes = await axios.post('https://open.tiktokapis.com/v2/oauth/token/', requestData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      }
    });
    
    if (tokenRes.data.error) {
      return res.status(400).send(`Error: ${tokenRes.data.error}, Description: ${tokenRes.data.error_description}`);
    }
    if (!tokenRes.data.access_token) {
      return res.status(400).send('Access token not received');
    }

    const { access_token, refresh_token, expires_in } = tokenRes.data;

    // Save tokens securely
    tokenStorage.saveTokens({
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000
    });

    // Clear code verifier after successful token exchange
    codeVerifier = null;

    res.send(`
      <h1>✅ Login Successful!</h1>
      <p>Tokens acquired and stored securely.</p>
      <h2>Available Endpoints:</h2>
      <ul>
        <li><a href="/creator-info">Creator Info</a> - Get your TikTok profile info</li>
        <li><a href="/user/info?fields=open_id,union_id,avatar_url,display_name,bio_description">User Info</a> - Get your TikTok user info</li>
        <li><a href="/health">Health Check</a> - Server status</li>
      </ul>
      <h3>API Usage:</h3>
      <pre>
POST /video/direct-post
{
  "file_path": "/path/to/video.mp4",
  "title": "Your video title"
}

GET /video/status?publish_id=YOUR_PUBLISH_ID
      </pre>
    `);
  } catch (err) {
    console.error('Token exchange error:', err.response?.data || err.message);
    res.status(500).send('Token exchange failed');
  }
});

// 3. Auto-refresh access token if expired
async function getValidAccessToken() {
  const tokens = tokenStorage.loadTokens();
  if (!tokens) {
    throw new Error(`No tokens available. Please complete OAuth flow first. Visit http://localhost:${PORT}/auth/login`);
  }

  if (Date.now() < tokens.expires_at - 60 * 1000) {
    return tokens.access_token;
  }

  console.log('Refreshing TikTok access token...');
  const refreshRes = await axios.post('https://open.tiktokapis.com/v2/oauth/token/', {
    client_key: process.env.TIKTOK_CLIENT_KEY,
    client_secret: process.env.TIKTOK_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
  });

  const { access_token, refresh_token, expires_in } = refreshRes.data;

  // Save new tokens
  tokenStorage.saveTokens({
    access_token,
    refresh_token,
    expires_at: Date.now() + expires_in * 1000
  });

  return access_token;
}

// 4. Test by calling TikTok API creator_info with access token
app.get('/creator-info', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();

    const profile = await axios.post('https://open.tiktokapis.com/v2/post/publish/creator_info/query/', {}, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      },
    });

    res.json(profile.data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send('API call failed');
  }
});

// 5. User info API - accepts fields from client and forwards to TikTok
app.get('/user/info', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();
    const { fields } = req.query;

    if (!fields) {
      return res.status(400).json({ 
        error: 'fields query parameter is required',
        example: 'GET /user/info?fields=open_id,union_id,avatar_url'
      });
    }

    const userInfoResponse = await axios.get(`https://open.tiktokapis.com/v2/user/info/?fields=${fields}`, {
      headers: {
        'Authorization': `Bearer ${access_token}`,
      }
    });

    res.json(userInfoResponse.data);
  } catch (err) {
    console.error('User info error:', err.response?.data || err.message);
    res.status(500).json({
      error: 'User info request failed',
      details: err.response?.data || err.message
    });
  }
});


let googleDriveUrl = ''
// 틱톡 서버가 실제 영상을 가져가는 통로 (스트리밍)
app.get('/temp-video-stream', async (req, res) => {
    // 주의: 실제 구현 시에는 n8n에서 받은 google_url을 DB나 변수에 임시 저장했다가 여기서 써야 합니다.
    // 일단 테스트를 위해 마지막으로 요청된 URL을 사용한다고 가정하거나 고정값으로 테스트해보세요.
    try {
        const videoResponse = await axios({
            method: 'get',
            url: googleDriveUrl,
            responseType: 'stream'
        });
        res.setHeader('Content-Type', 'video/mp4');
        videoResponse.data.pipe(res);
    } catch (e) {
        res.status(500).send("Video streaming failed");
    }
});

// 6. Simple video upload API - takes file path and title
app.post('/video/direct-post', async (req, res) => {
    const { video_url, caption } = req.body;
    const accessToken = await getValidAccessToken(); // 프로젝트 내부의 토큰 관리 함수 활용
    googleDriveUrl = video_url

    try {
        // 1. 틱톡에 '내 도메인'의 영상을 가져가라고 초기화 요청을 보냅니다.
        // (실제 파일은 틱톡이 내 서버로 다시 요청할 때 보내줍니다)
        const response = await axios.post(
            'https://open.tiktokapis.com/v2/post/publish/inbox/video/init/',
            {
                "post_info": {
                    "caption": caption || "New Video",
                    "privacy_level": "PUBLIC_TO_EVERYONE",
                    "disable_comment": false
                },
                "source_info": {
                    "source": "PULL_FROM_URL",
                    "video_url": "https://www.acaxiaa.store/temp-video-stream" // 틱톡이 찌를 내 서버 주소
                }
            },
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json; charset=UTF-8'
                }
            }
        );

        // 2. 틱톡 서버가 내 서버(temp-video-stream)로 파일을 요청할 때 
        // 구글 드라이브의 파일을 스트리밍해주는 엔드포인트를 아래에 별도로 만듭니다.
        
        res.json({ success: true, data: response.data });
    } catch (error) {
        console.error('TikTok API Error:', error.response ? error.response.data : error.message);
        res.status(500).json({ success: false, error: error.response ? error.response.data : error.message });
    }
});

// 틱톡 영상 통계 가져오기 엔드포인트
app.post('/video/metrics', async (req, res) => {
    const { publish_id } = req.body;
    const accessToken = await getValidAccessToken(); // token.json에서 토큰 읽어오는 기존 로직 활용
	
	console.log(req.body)
    try {
        // [2단계] publish_id를 사용하여 public_video_id 확보
        const statusResponse = await axios.post(
            'https://open.tiktokapis.com/v2/post/publish/status/fetch/',
	    {
                publish_id: publish_id
            },
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json; charset=UTF-8'
                },
            }
        );

        const videoId = statusResponse.data.data.publicaly_available_post_id[0];
	console.log(videoId, statusResponse.data)

        if (!videoId) {
            return res.json({ 
                success: false, 
                status: statusResponse.data.data.status,
                message: "아직 영상이 처리 중이거나 Video ID가 생성되지 않았습니다." 
            });
        }

//test
// [검증 로직] 내 계정의 실제 ID들과 대조해보기
const listResponse = await axios.post(
    'https://open.tiktokapis.com/v2/video/list/',
    {}, 
    {
        headers: { 'Authorization': `Bearer ${accessToken}` },
        params: { "fields": "id,title" } 
    }
);
console.log("listResponse: ", listResponse.data)

// listResponse에서 온 id들이 진짜 API가 인식하는 '살아있는' ID들입니다.
console.log("실제 조회 가능한 ID 목록:", listResponse.data.data.videos.map(v => v.id));

//test

        // [3단계] 확보한 videoId로 상세 통계(Statistics) 조회
        const metricsResponse = await axios.post(
            'https://open.tiktokapis.com/v2/video/query/',
            {
                "filters": {
                    "video_ids": [videoId]
                }
            },
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json',
                },
                params: {
                    "fields": "id,title,like_count,comment_count_share_count,view_count" // 통계 필드 명시 필수
                }
            }
        );

        // n8n으로 최종 결과 반환
        const stats = metricsResponse.data.data.videos[0].statistics;
        res.json({
            success: true,
            video_id: videoId,
            metrics: {
                view_count: stats.view_count,
                like_count: stats.like_count,
                share_count: stats.share_count,
                comment_count: stats.comment_count
            }
        });

    } catch (error) {
        console.error('Metrics Error:', error.response ? error.response.data : error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 7. Check video upload status using query parameters
app.get('/video/status', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();
    const { publish_id } = req.query;

    if (!publish_id) {
      return res.status(400).json({ error: 'publish_id query parameter is required' });
    }

    const statusResponse = await axios.post('https://open.tiktokapis.com/v2/post/publish/status/fetch/', {
      publish_id: publish_id
    }, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      }
    });

    res.json(statusResponse.data);

  } catch (err) {
    console.error('Status check error:', err.response?.data || err.message);
    res.status(500).json({
      error: 'Status check failed',
      details: err.response?.data || err.message
    });
  }
});

// 8. Video upload API - proxies TikTok's content upload API with FILE_UPLOAD approach (2-step process)
app.post('/video/upload', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();
    const { file_path } = req.body;

    if (!file_path) {
      return res.status(400).json({ error: 'file_path is required' });
    }

    // Check if file exists
    if (!fs.existsSync(file_path)) {
      return res.status(400).json({ error: 'File not found at specified path' });
    }

    // Get file stats
    const stats = fs.statSync(file_path);
    const fileSize = stats.size;
    const chunkSize = (fileSize < 10 * 1024 * 1024) ? fileSize : 10 * 1024 * 1024; // 10MB chunks
    const totalChunkCount = Math.ceil(fileSize / chunkSize);

    console.log('Starting video upload process...');
    console.log('File info:', { path: file_path, size: fileSize, size_mb: (fileSize / 1024 / 1024).toFixed(2) });

    // Step 1: Initialize video upload
    console.log('Step 1: Initializing video upload...');
    const initResponse = await axios.post('https://open.tiktokapis.com/v2/post/publish/inbox/video/init/', {
      source_info: {
        source: 'FILE_UPLOAD',
        video_size: fileSize,
        chunk_size: chunkSize,
        total_chunk_count: totalChunkCount
      }
    }, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      }
    });

    if (initResponse.data.error && initResponse.data.error.code !== 'ok') {
      throw new Error(`TikTok API Error: ${initResponse.data.error.message}`);
    }

    const { publish_id, upload_url } = initResponse.data.data;
    console.log('Upload initialized:', { publish_id, upload_url });

    // Step 2: Upload video file to TikTok's designated URL
    console.log('Step 2: Uploading video file...');
    console.log('Upload URL:', upload_url);
    console.log('File size:', fileSize, 'bytes');
    console.log('Content-Range:', `bytes 0-${fileSize - 1}/${fileSize}`);
    console.log('Content-Length:', fileSize);
    
    const videoBuffer = fs.readFileSync(file_path);
    console.log('Video buffer loaded, size:', videoBuffer.length, 'bytes');
    
    const uploadHeaders = {
      'Content-Range': `bytes 0-${fileSize - 1}/${fileSize}`,
      'Content-Type': 'video/mp4',
      'Content-Length': fileSize
    };
    console.log('Upload headers:', uploadHeaders);
    
    const uploadResponse = await axios.put(upload_url, videoBuffer, {
      headers: uploadHeaders,
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    console.log('Upload response status:', uploadResponse.status);
    console.log('Upload response headers:', uploadResponse.headers);
    console.log('Upload response data:', uploadResponse.data);
    console.log('Video uploaded to inbox successfully');

    // Return success response with publish_id
    res.json({
      success: true,
      message: 'Video uploaded to TikTok inbox successfully. User must complete editing flow in TikTok app.',
      data: {
        publish_id: publish_id,
        file_info: {
          path: file_path,
          size: fileSize,
          size_mb: (fileSize / 1024 / 1024).toFixed(2)
        },
        note: 'Video is now in TikTok inbox. User must click on inbox notifications to continue the editing flow in TikTok and complete the post.'
      }
    });

  } catch (err) {
    console.error('Video upload error:', err.response?.data || err.message);
    res.status(500).json({
      error: 'Video upload failed',
      details: err.response?.data || err.message
    });
  }
});

// 9. Shutdown endpoint - gracefully shut down the server
app.post('/shutdown', (req, res) => {
  console.log('🛑 Shutdown request received...');
  
  // Send immediate response to client
  res.json({
    success: true,
    message: 'Server shutdown initiated',
    timestamp: new Date().toISOString()
  });

  // Gracefully shut down the server after a short delay
  setTimeout(() => {
    console.log('🔄 Shutting down server...');
    
    // Try to kill the parent process (nodemon, pm2, etc.) if possible
    const parentPid = process.ppid;
    if (parentPid && parentPid !== 1) {
      try {
        console.log(`🔄 Attempting to kill parent process (PID: ${parentPid})...`);
        process.kill(parentPid, 'SIGTERM');
        
        // Give parent process a moment to shut down gracefully
        setTimeout(() => {
          console.log('🔄 Exiting current process...');
          process.exit(0);
        }, 2000);
      } catch (error) {
        console.log('⚠️ Could not kill parent process, exiting current process only...');
        process.exit(0);
      }
    } else {
      console.log('🔄 Exiting current process...');
      process.exit(0);
    }
  }, 1000); // 1 second delay to ensure response is sent
});


// add your own api endpoint here

app.listen(PORT, () => {
  console.log(`🚀 TikTok OAuth2 Server running at http://localhost:${PORT}`);
  console.log(`📖 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 Perform OAuth flow: http://localhost:${PORT}/auth/login`);
  console.log(`🛑 Shutdown: POST http://localhost:${PORT}/shutdown`);
});

setInterval(getValidAccessToken, SIX_HOURS);