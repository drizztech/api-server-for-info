import express from 'express';
import dotenv from 'dotenv';
import { GoogleGenerativeAI } from '@google/generative-ai';
import axios from 'axios';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ============= CONFIGURATION =============
const OLLAMA_BASE_URL = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL || 'http://localhost:3001';
const PORT = parseInt(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || './data';

// Validate required environment variables
if (!GEMINI_API_KEY) {
  throw new Error('GEMINI_API_KEY environment variable is not set.');
}

// Initialize Gemini
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

// ============= DATABASE LAYER =============
class DataManager {
  constructor() {
    this.dataDir = DATA_DIR;
    this.ensureDataDir();
  }

  ensureDataDir() {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
  }

  // API Requests Tracking
  saveApiRequest(requestData) {
    const timestamp = new Date().toISOString();
    const requestWithMeta = {
      id: `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp,
      ...requestData,
    };

    const filePath = path.join(this.dataDir, 'api-requests.jsonl');
    fs.appendFileSync(filePath, JSON.stringify(requestWithMeta) + '\n');
    return requestWithMeta;
  }

  getApiRequests(limit = 100, offset = 0) {
    const filePath = path.join(this.dataDir, 'api-requests.jsonl');
    if (!fs.existsSync(filePath)) return [];

    const lines = fs.readFileSync(filePath, 'utf-8').trim().split('\n');
    return lines
      .filter(line => line.length > 0)
      .map(line => JSON.parse(line))
      .reverse()
      .slice(offset, offset + limit);
  }

  getApiStats() {
    const filePath = path.join(this.dataDir, 'api-requests.jsonl');
    if (!fs.existsSync(filePath)) {
      return {
        totalRequests: 0,
        successCount: 0,
        errorCount: 0,
        averageResponseTime: 0,
        endpoints: {},
      };
    }

    const lines = fs.readFileSync(filePath, 'utf-8').trim().split('\n');
    const requests = lines.filter(line => line.length > 0).map(line => JSON.parse(line));

    const stats = {
      totalRequests: requests.length,
      successCount: requests.filter(r => r.statusCode >= 200 && r.statusCode < 300).length,
      errorCount: requests.filter(r => r.statusCode >= 400).length,
      averageResponseTime: requests.reduce((sum, r) => sum + (r.responseTime || 0), 0) / requests.length || 0,
      endpoints: {},
      statusCodes: {},
      hourlyDistribution: {},
    };

    requests.forEach(req => {
      // Endpoint stats
      if (!stats.endpoints[req.endpoint]) {
        stats.endpoints[req.endpoint] = { count: 0, errors: 0, totalTime: 0 };
      }
      stats.endpoints[req.endpoint].count++;
      stats.endpoints[req.endpoint].totalTime += req.responseTime || 0;
      if (req.statusCode >= 400) stats.endpoints[req.endpoint].errors++;

      // Status code distribution
      stats.statusCodes[req.statusCode] = (stats.statusCodes[req.statusCode] || 0) + 1;

      // Hourly distribution
      const hour = new Date(req.timestamp).getHours();
      stats.hourlyDistribution[hour] = (stats.hourlyDistribution[hour] || 0) + 1;
    });

    return stats;
  }

  // Project Progress Tracking
  saveProjectProgress(projectData) {
    const filePath = path.join(this.dataDir, 'project-progress.json');
    const existing = this.getProjectProgress();
    const updated = {
      ...existing,
      ...projectData,
      lastUpdated: new Date().toISOString(),
    };
    fs.writeFileSync(filePath, JSON.stringify(updated, null, 2));
    return updated;
  }

  getProjectProgress() {
    const filePath = path.join(this.dataDir, 'project-progress.json');
    if (!fs.existsSync(filePath)) {
      return {
        projectName: 'AI Orchestrator Server',
        version: '1.0.0',
        status: 'active',
        milestone: 0,
        totalMilestones: 10,
        features: [],
        bugs: [],
        lastUpdated: new Date().toISOString(),
      };
    }
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  }

  // Tool Metrics & Growth Tracking
  recordToolMetric(toolName, metricData) {
    const filePath = path.join(this.dataDir, 'tool-metrics.jsonl');
    const metric = {
      id: `metric_${Date.now()}`,
      timestamp: new Date().toISOString(),
      tool: toolName,
      ...metricData,
    };
    fs.appendFileSync(filePath, JSON.stringify(metric) + '\n');
    return metric;
  }

  getToolMetrics(toolName = null, limit = 500) {
    const filePath = path.join(this.dataDir, 'tool-metrics.jsonl');
    if (!fs.existsSync(filePath)) return [];

    const lines = fs.readFileSync(filePath, 'utf-8').trim().split('\n');
    let metrics = lines
      .filter(line => line.length > 0)
      .map(line => JSON.parse(line));

    if (toolName) {
      metrics = metrics.filter(m => m.tool === toolName);
    }

    return metrics.slice(-limit);
  }

  getToolGrowthAnalytics(toolName = null) {
    const metrics = this.getToolMetrics(toolName, 1000);
    if (metrics.length === 0) {
      return { trend: 'insufficient_data', dataPoints: 0 };
    }

    const tools = toolName ? { [toolName]: metrics } : {};
    if (!toolName) {
      metrics.forEach(m => {
        if (!tools[m.tool]) tools[m.tool] = [];
        tools[m.tool].push(m);
      });
    }

    const analytics = {};
    Object.entries(tools).forEach(([tool, data]) => {
      const successCount = data.filter(d => d.success).length;
      const errorCount = data.filter(d => !d.success).length;
      const successRate = (successCount / data.length) * 100;

      analytics[tool] = {
        totalExecutions: data.length,
        successCount,
        errorCount,
        successRate: successRate.toFixed(2),
        averageExecutionTime: (data.reduce((sum, d) => sum + (d.executionTime || 0), 0) / data.length).toFixed(2),
        trend: successRate > 85 ? 'growing' : successRate > 70 ? 'stable' : 'declining',
        firstSeen: data[0].timestamp,
        lastSeen: data[data.length - 1].timestamp,
      };
    });

    return analytics;
  }
}

const dataManager = new DataManager();

// ============= AI ORCHESTRATOR =============
class AIOrchestrator {
  constructor() {
    this.conversationHistory = [];
    this.toolResults = [];
  }

  async queryOllamaThinking(prompt, systemContext = '') {
    try {
      const response = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
        model: 'kimi-k2-thinking:cloud',
        prompt: prompt,
        system: systemContext,
        stream: false,
      }, { timeout: 60000 });

      return {
        model: 'kimi-k2-thinking',
        thinking: response.data.response,
        completedAt: new Date(),
      };
    } catch (error) {
      console.error('Ollama Kimi error:', error.message);
      throw new Error(`Ollama service error: ${error.message}`);
    }
  }

  async queryGemini(prompt, systemContext = '', useThinkingContext = null) {
    try {
      let fullPrompt = systemContext ? `${systemContext}\n\n${prompt}` : prompt;

      if (useThinkingContext) {
        fullPrompt = `Context from deep reasoning:\n${useThinkingContext}\n\n${fullPrompt}`;
      }

      const model = genAI.getGenerativeModel({
        model: 'gemini-2.0-flash',
        generationConfig: {
          temperature: 0.7,
          topP: 0.9,
          topK: 40,
          maxOutputTokens: 2048,
        }
      });

      const result = await model.generateContent(fullPrompt);
      const response = await result.response;
      const text = response.text();

      return {
        model: 'gemini',
        response: text,
        completedAt: new Date(),
      };
    } catch (error) {
      console.error('Gemini error:', error.message);
      throw new Error(`Gemini API error: ${error.message}`);
    }
  }

  async callMCPTools(toolRequest) {
    try {
      const response = await axios.post(`${MCP_SERVER_URL}/tools/execute`, {
        tool: toolRequest.tool,
        arguments: toolRequest.arguments,
      }, { timeout: 30000 });

      return {
        toolName: toolRequest.tool,
        result: response.data,
        success: true,
      };
    } catch (error) {
      console.error('MCP tool error:', error.message);
      return {
        toolName: toolRequest.tool,
        error: error.message,
        success: false,
      };
    }
  }

  async orchestrate(userRequest, automationNeeded = false) {
    const startTime = Date.now();
    const workflow = {
      request: userRequest,
      stages: [],
      finalResponse: null,
    };

    try {
      console.log('[Stage 1] Initiating deep reasoning with Ollama...');
      const thinkingResult = await this.queryOllamaThinking(
        userRequest,
        'You are an expert problem solver. Analyze the request deeply and provide structured reasoning.'
      );
      workflow.stages.push({ stage: 'thinking', result: thinkingResult });

      console.log('[Stage 2] Analyzing required tools with Gemini...');
      const toolAnalysisPrompt = `
Based on this request: "${userRequest}"

And this reasoning: "${thinkingResult.thinking}"

Identify what tools/OS-level operations are needed. Respond in JSON format:
{
  "tools": ["tool_name1", "tool_name2"],
  "reasoning": "explanation"
}
`;
      const toolAnalysis = await this.queryGemini(
        toolAnalysisPrompt,
        '',
        thinkingResult.thinking
      );

      let toolsNeeded = [];
      try {
        const jsonMatch = toolAnalysis.response.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          toolsNeeded = parsed.tools || [];
        }
      } catch (e) {
        console.log('Could not parse tool analysis JSON');
      }

      workflow.stages.push({ stage: 'toolAnalysis', result: toolAnalysis });

      if (automationNeeded && toolsNeeded.length > 0) {
        console.log('[Stage 3] Executing OS automation via MCP...');
        const toolResults = [];

        for (const tool of toolsNeeded) {
          const toolResult = await this.callMCPTools({
            tool: tool,
            arguments: { userContext: userRequest },
          });
          toolResults.push(toolResult);
          
          // Record tool metric
          dataManager.recordToolMetric(tool, {
            success: toolResult.success,
            executionTime: Date.now() - startTime,
            userRequest: userRequest.substring(0, 100),
          });
        }

        workflow.stages.push({ stage: 'osAutomation', results: toolResults });
      }

      console.log('[Stage 4] Synthesizing final response...');
      let finalPrompt = `
Provide a comprehensive response to: "${userRequest}"

Consider the deep reasoning and analysis provided.
`;
      if (workflow.stages[3]?.results) {
        finalPrompt += `\nTool execution results: ${JSON.stringify(workflow.stages[3].results)}`;
      }

      const finalResponse = await this.queryGemini(
        finalPrompt,
        'Synthesize all information into a clear, actionable response.'
      );

      workflow.finalResponse = finalResponse;
      workflow.completedAt = new Date();
      workflow.executionTimeMs = Date.now() - startTime;

      return workflow;
    } catch (error) {
      workflow.error = error.message;
      workflow.executionTimeMs = Date.now() - startTime;
      return workflow;
    }
  }
}

const orchestrator = new AIOrchestrator();

// ============= MIDDLEWARE =============
const requestTrackingMiddleware = (req, res, next) => {
  const startTime = Date.now();
  const originalJson = res.json;

  res.json = function(data) {
    const responseTime = Date.now() - startTime;
    const statusCode = res.statusCode;

    dataManager.saveApiRequest({
      method: req.method,
      endpoint: req.path,
      statusCode,
      responseTime,
      userAgent: req.get('user-agent'),
      ip: req.ip,
      requestSize: JSON.stringify(req.body).length,
      responseSize: JSON.stringify(data).length,
    });

    return originalJson.call(this, data);
  };

  next();
};

app.use(requestTrackingMiddleware);

// ============= API ROUTES =============

// Home - Serves dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check
app.get('/api/health', async (req, res) => {
  const health = {
    status: 'unknown',
    checks: {
      ollama: 'unchecked',
      gemini: 'unchecked',
      mcp: 'unchecked',
    },
    timestamp: new Date(),
  };

  try {
    await axios.get(`${OLLAMA_BASE_URL}/api/tags`, { timeout: 5000 });
    health.checks.ollama = 'healthy';
  } catch (e) {
    health.checks.ollama = 'unhealthy';
  }

  health.checks.gemini = GEMINI_API_KEY ? 'configured' : 'unconfigured';

  try {
    await axios.get(`${MCP_SERVER_URL}/health`, { timeout: 5000 });
    health.checks.mcp = 'healthy';
  } catch (e) {
    health.checks.mcp = 'unhealthy or unavailable';
  }

  const allHealthy = Object.values(health.checks).every(c => c === 'healthy' || c === 'configured');
  health.status = allHealthy ? 'healthy' : 'degraded';

  res.json(health);
});

// Orchestrate multi-agent workflow
app.post('/api/orchestrate', async (req, res) => {
  try {
    const { request, automation = false } = req.body;

    if (!request) {
      return res.status(400).json({ error: 'Request prompt is required' });
    }

    const result = await orchestrator.orchestrate(request, automation);
    res.json(result);
  } catch (error) {
    console.error('Orchestration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Direct Ollama Kimi query
app.post('/api/think', async (req, res) => {
  try {
    const { prompt, systemContext = '' } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    const result = await orchestrator.queryOllamaThinking(prompt, systemContext);
    res.json(result);
  } catch (error) {
    console.error('Think error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Direct Gemini query
app.post('/api/generate', async (req, res) => {
  try {
    const { prompt, systemContext = '' } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    const result = await orchestrator.queryGemini(prompt, systemContext);
    res.json(result);
  } catch (error) {
    console.error('Generate error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Execute MCP tool directly
app.post('/api/execute-tool', async (req, res) => {
  try {
    const { tool, arguments: args } = req.body;

    if (!tool) {
      return res.status(400).json({ error: 'Tool name is required' });
    }

    const startTime = Date.now();
    const result = await orchestrator.callMCPTools({
      tool,
      arguments: args || {},
    });

    dataManager.recordToolMetric(tool, {
      success: result.success,
      executionTime: Date.now() - startTime,
    });

    res.json(result);
  } catch (error) {
    console.error('Tool execution error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============= ANALYTICS ROUTES =============

// Get API requests
app.get('/api/analytics/requests', (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  const requests = dataManager.getApiRequests(limit, offset);
  res.json({ requests, total: requests.length });
});

// Get API statistics
app.get('/api/analytics/stats', (req, res) => {
  const stats = dataManager.getApiStats();
  res.json(stats);
});

// Get project progress
app.get('/api/project/progress', (req, res) => {
  const progress = dataManager.getProjectProgress();
  res.json(progress);
});

// Update project progress
app.post('/api/project/progress', (req, res) => {
  try {
    const updated = dataManager.saveProjectProgress(req.body);
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get tool metrics
app.get('/api/analytics/tools', (req, res) => {
  const toolName = req.query.tool || null;
  const limit = parseInt(req.query.limit) || 500;
  const metrics = dataManager.getToolMetrics(toolName, limit);
  res.json({ metrics, total: metrics.length });
});

// Get tool growth analytics
app.get('/api/analytics/tools/growth', (req, res) => {
  const toolName = req.query.tool || null;
  const analytics = dataManager.getToolGrowthAnalytics(toolName);
  res.json(analytics);
});

// Record custom metric
app.post('/api/analytics/metric', (req, res) => {
  try {
    const { toolName, metricData } = req.body;
    if (!toolName) {
      return res.status(400).json({ error: 'toolName is required' });
    }
    const metric = dataManager.recordToolMetric(toolName, metricData);
    res.json(metric);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 AI Orchestrator Server running on port ${PORT}`);
  console.log(`📍 Dashboard: http://localhost:${PORT}`);
  console.log(`📍 Ollama endpoint: ${OLLAMA_BASE_URL}`);
  console.log(`📍 MCP Server endpoint: ${MCP_SERVER_URL}`);
  console.log(`📍 Gemini API: ${GEMINI_API_KEY ? 'Configured' : 'Not configured'}`);
});
