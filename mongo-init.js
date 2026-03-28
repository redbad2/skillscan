// MongoDB初始化脚本

// 切换到skillscan数据库
db = db.getSiblingDB('skillscan');

// 创建集合
db.createCollection('skills');
db.createCollection('vulnerabilities');
db.createCollection('configurations');
db.createCollection('scan_tasks');

// 创建索引
// Skills集合索引
db.skills.createIndex({ "skill_id": 1 }, { unique: true });
db.skills.createIndex({ "platform": 1, "language": 1 });
db.skills.createIndex({ "scan_status": 1 });
db.skills.createIndex({ "scan_result.risk_level": 1 });
db.skills.createIndex({ "metadata.created_at": -1 });

// Vulnerabilities集合索引
db.vulnerabilities.createIndex({ "vulnerability_id": 1 }, { unique: true });
db.vulnerabilities.createIndex({ "skill_id": 1 });
db.vulnerabilities.createIndex({ "category": 1, "pattern": 1 });
db.vulnerabilities.createIndex({ "severity": 1 });
db.vulnerabilities.createIndex({ "detected_at": -1 });

// Configurations集合索引
db.configurations.createIndex({ "config_type": 1, "language": 1 }, { unique: true });

// Scan tasks集合索引
db.scan_tasks.createIndex({ "task_id": 1 }, { unique: true });
db.scan_tasks.createIndex({ "status": 1 });
db.scan_tasks.createIndex({ "created_at": -1 });

// 插入默认配置
db.configurations.insertOne({
  config_type: "thresholds",
  language: "all",
  thresholds: [
    { name: "confidence_threshold", value: 0.7, description: "静态分析置信度阈值" },
    { name: "llm_confirm_threshold", value: 0.6, description: "LLM分析确认阈值" },
    { name: "override_threshold", value: 0.8, description: "推翻静态发现阈值" },
    { name: "risk_score_threshold", value: 0.5, description: "综合风险评分阈值" },
  ],
  updated_at: new Date(),
  updated_by: "system",
  version: 1,
  description: "默认阈值配置",
  enabled: true
});

print("MongoDB initialization completed!");
