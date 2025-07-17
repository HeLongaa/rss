# RSS Subscription Service

![Express](https://img.shields.io/badge/Express-4.18+-blue.svg)
![Node.js](https://img.shields.io/badge/Node.js-14+-green.svg)
![GitHub OAuth](https://img.shields.io/badge/GitHub-OAuth-black.svg)
![Tailwind CSS](https://img.shields.io/badge/Tailwind-2.2+-cyan.svg)
![RSS Parser](https://img.shields.io/badge/RSS--Parser-3.13+-orange.svg)
![License](https://img.shields.io/badge/License-MIT-red.svg)

一个现代化的RSS订阅服务，支持GitHub认证和实时RSS更新。

是[RSS-Subscription](https://github.com/HeLongaa/RSS-Subscription) 的nodejs版本

## ✨ 特性

- 🔐 GitHub OAuth认证
- 📡 实时RSS订阅更新
- 🎨 现代化UI设计
- 🔄 可配置的更新间隔
- 📱 响应式布局
- 📚 内置API文档

## 🚀 快速开始

### 前置要求

- Node.js 14+
- GitHub OAuth应用凭证

### 安装

```bash
# 克隆仓库
git clone https://github.com/HeLongaa/rss.git

# 进入项目目录
cd rss

# 安装依赖
npm install
```

### 配置

1. 创建 `.env` 文件：

```env
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
SESSION_SECRET=your_session_secret
AUTHORIZED_USERS=user1,user2
```

2. 在GitHub设置OAuth应用回调URL：
   - 开发环境：`http://localhost:3000/auth/github/callback`
   - 生产环境：`https://your-domain.com/auth/github/callback`

### 运行

```bash
# 开发环境
npm run dev

# 生产环境
npm start
```

## 📖 API文档

### 获取RSS数据
```
GET /api/rss
```

### 手动刷新RSS
```
POST /api/refresh
```

### 更新刷新间隔
```
POST /api/update-interval
Body: { "interval": number }
```

## 🌐 部署

本项目已配置好Vercel部署文件，可以直接部署到Vercel平台：

1. Fork本仓库
2. 在Vercel中导入项目
3. 配置环境变量
4. 完成部署

## 🛠️ 技术栈

- Express.js - Web框架
- Passport.js - 认证中间件
- GitHub OAuth - 用户认证
- Tailwind CSS - 样式框架
- RSS Parser - RSS解析

## 📝 许可证

MIT License - 查看 [LICENSE](LICENSE) 文件了解更多详情

## 🤝 贡献

欢迎提交Issue和Pull Request！

1. Fork本仓库
2. 创建特性分支
3. 提交改动
4. 推送到分支
5. 创建Pull Request

## 📬 联系方式

如有问题或建议，欢迎创建Issue或直接联系项目维护者。
