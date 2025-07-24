#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os,re,io,time,uuid,json,httpx,asyncio,logging
import sqlite3
from pathlib import Path
from contextlib import asynccontextmanager
from pypdf import PdfReader
from pydantic import BaseModel, HttpUrl, RootModel
from typing import List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.hunyuan.v20230901 import hunyuan_client, models

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PDF-Audit-API")

#关键词定位截断
SENTENCES="对其他来源资金的经费来源、资金具体开支用途做简要说明。"

# 创建临时目录
TEMP_DIR = Path("temp")
TEMP_DIR.mkdir(exist_ok=True)

# 并发控制
MAX_CONCURRENT = 5
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

# 固定的49条审查规则
FIXED_AUDIT_RULES = [
    "1. 整体篇幅对比国自然同类别项目是否合适",
    "2. 全文格式是否规范（字体行距统一/标题序号匹配/空格检查）",
    "3. 全文是否存在低级错误（错别字/缺字漏字）",
    "4. 文中使用的专业术语是否表述正确",
    "5. 文中涉及到的英文表述是否正确",
    "6. 全文是否逻辑清晰，分点分层展示",
    "7. 全文是否附有图文",
    "8. 全文展示的图下方是否有图注作解释说明",
    "9. 全文展示的图是否在正文中有对应标注",
    "10. 全文前后表述是否一致",
    "11. 全文对于第一次出现的专业词汇是否有进行解释",
    "12. 全文是否存在过于口语化的表述",
    "13. 项目名称是否包含研究对象、研究领域、研究类型",
    "14. 项目名称是否与神经或肿瘤药物研发有关（一票否决）",
    "15. 项目名称是否逻辑正确，是否清晰明确",
    "16. 项目名称是否与研究内容吻合",
    "17. 项目摘要是否包含1）研究背景+待解决的问题 2）前期结果+假说+内容 3）研究意义",
    "18. 立项依据是否包含1）课题背景2）研究现状3）当前亟待解决的问题",
    "19. 立项依据是否结合对应文献和前期结果",
    "20. 立项依据部分，引用文献对应的内容是否真实",
    "21. 参考文献是否在30-50篇之间",
    "22. 参考文献是否保持格式统一",
    "23. 参考文献中是否包含近5年的研究，引用近5年研究的数量是否合适",
    "24. 立项依据部分是否有子标题，是否有下划线/加粗等标注突出重点",
    "25. 立项依据是否附有图文",
    "26. 立项依据部分所有文字是否超过4000字",
    "27. 研究内容是否分阶段、分方面展示",
    "28. 研究方案中的样本量是否合理",
    "29. 研究方案中的样本量是否有对应的理论依据",
    "30. 拟采取的研究方案和可行性分析是否分点分节说明",
    "31. 是否有技术路线图",
    "32. 技术路线图是否清晰",
    "33. 研究内容、研究目标以及拟解决的关键科学问题部分所有文字是否超过4000字",
    "34. 项目研究的内容在同领域中，是否已经存在很多已发表的研究成果",
    "35. 项目是否具备转化价值",
    "36. 项目能否解决当下该研究领域内的痛点难点",
    "37. 项目是否有区别于其他同类研究的亮点",
    "38. 项目研究计划是否分时间节点或分阶段展示",
    "39. 项目产出的成果是否可衡量",
    "40. 项目产出的成果是否有含金量",
    "41. 项目是否可以在2年内达到预期成果",
    "42. 申请人及团队的研究领域与课题研究方向是否匹配",
    "43. 申请人及团队所在单位是否具备完成项目所需要的技术条件",
    "44. 申请人团队成员组成是否合理",
    "45. 申请人及团队的分工是否清晰，细化",
    "46. 申请人简介中，申请人发表的文章是否标注影响因子",
    "47. 申请人简介中，申请人发表的文章是否体现本人排序",
    "48. 申请人简介中，申请人发表的文章是否与本项目研究内容相关",
    "49. 项目经费预算中，参照国自然同类项目，申请人填写的是否合理"
]

# 请求模型
class AuditItem(BaseModel):
    url: HttpUrl
    id: str

class AuditRequest(RootModel):
    root: List[AuditItem]
    
    def __iter__(self):
        return iter(self.root)
    
    def __getitem__(self, item):
        return self.root[item]
    
    def __len__(self):
        return len(self.root)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用启动时清理临时文件与缓存"""
    logger.info("🔧 应用启动，清理旧临时文件...")
    now = time.time()
    for file in TEMP_DIR.glob("*.md"):
        if file.stat().st_mtime < now - 1 * 86400:  # 1天
            try:
                file.unlink()
                logger.info(f"清理旧临时文件: {file}")
            except Exception as e:
                logger.warning(f"清理文件失败: {file} - {str(e)}")
    logger.info("🔧 临时文件清理完成")

    yield  # 这里是应用运行的地方

app = FastAPI(title="内容审查", lifespan=lifespan)

def convert_httpurl_to_string(url) -> str:
    """将 HttpUrl 对象安全转换为字符串，处理中文编码问题"""
    if hasattr(url, '__str__'):
        return str(url)
    elif isinstance(url, str):
        return url
    return ""

def extract_filename_from_url(url: str) -> str:
    """从URL提取原始文件名"""
    # 移除URL参数
    clean_url = url.split('?')[0]
    # 提取文件名
    filename = os.path.basename(clean_url)
    # 替换非法字符
    return re.sub(r'[^\w_.-]', '_', filename) or "unknown.pdf"

def build_audit_prompt(pdf_text: str) -> str:

    attitude_rule_indices = [2, 3, 4, 5, 8, 9, 10, 11, 12, 14, 22]

    attitude_rules_text = ", ".join([f"第{i}条" for i in attitude_rule_indices])
    ability_rules_text = ", ".join([f"第{i}条" for i in range(1, 50) if i not in attitude_rule_indices])

    return f"""
你是一个形式审查员。请根据以下49条规则，对这份PDF内容进行逐条审查。

### 输出要求：
- 输出为json形式，每条规则对应一项，需要按照1~49顺序输出，禁止乱序；
- 每项包含三个字段："规则内容（需带规则序号）"、"评估结果"、"理由"；
- "评估结果"必须为：`符合`、`不符合`；
- 如为 `不符合`，必须填写简要理由。

### 规则分类说明：
- **态度类规则**共11条，编号为：{attitude_rules_text}；
- **能力类规则**共38条，编号为：{ability_rules_text}；
- 其中**第14条**为“一票否决”，如不合格，必须重点标注；
- 最后请额外输出一份统计：
  - "态度类不合格数量"（不符合计1分，括号中需要输出不符合的规则序号）；
  - "能力类不合格数量"（不符合计1分，括号中需要输出不符合的规则序号）；
  - 是否触发第14条一票否决（True/False）。

### 评审规则如下：
{chr(10).join(FIXED_AUDIT_RULES)}

PDF内容如下：
{pdf_text}
"""


def extract_pdf_text(file_bytes: bytes, filename: str) -> str:
    """提取PDF文本并保存临时文件（使用原始文件名）"""
    try:
        # 清理文件名 - 确保文件名短小且安全
        safe_name = filename.replace('%', '_')  # 移除URL编码字符
        safe_name = re.sub(r'[^\w_.-]', '_', safe_name)[:100]  # 限制长度并替换非法字符
        if not safe_name:
            safe_name = "temp_pdf"
            
        temp_file = TEMP_DIR / f"{safe_name}.md"
        
        # 确保文件名不会过长
        max_length = 100  # 最大文件名长度
        if len(str(temp_file)) > max_length:
            # 如果路径过长，使用UUID生成短文件名
            safe_name = str(uuid.uuid4())[:8]
            temp_file = TEMP_DIR / f"{safe_name}.md"
        
        # 提取PDF文本
        reader = PdfReader(io.BytesIO(file_bytes))
        
        # 提取文本并处理可能的编码问题
        text_parts = []
        for page in reader.pages:
            page_text = page.extract_text() or ""
            # 清理文本中的代理对字符
            try:
                # 优先尝试使用utf-8编码
                encoded_text = page_text.encode('utf-8')
                # 如果成功编码为utf-8，则不需要额外处理
                text_parts.append(page_text)
            except UnicodeEncodeError as utf8_error:
                logger.warning(f"UTF-8编码失败，尝试其他编码方式: {str(utf8_error)}")
                try:
                    # 尝试使用utf-16编码处理代理对字符
                    page_text = page_text.encode('utf-16', 'surrogatepass').decode('utf-16', 'replace')
                    text_parts.append(page_text)
                except Exception as encoding_error:
                    logger.warning(f"UTF-16编码处理警告: {str(encoding_error)}")
                    # 如果上述方法都失败，使用替换策略
                    page_text = page_text.encode('utf-8', 'replace').decode('utf-8')
                    text_parts.append(page_text)
        
        text_content = "\n".join(text_parts)
        
        # 保存提取的文本到临时文件
        with open(temp_file, "w", encoding="utf-8", errors="ignore") as f:
            f.write(text_content)
        logger.info(f"📄 已保存提取文本到临时文件: {temp_file}")
        
        #关键词处截断文本
        match=re.search(re.escape(SENTENCES),text_content)
        if match:
            truncated_text=text_content[:match.end()]
            logger.info(f"✅ 已在关键词位置截断文本，原始长度: {len(text_content)}, 截断后长度: {len(truncated_text)}")
            return truncated_text
        else:
            return text_content
        
    except Exception as e:
        logger.error(f"PDF解析失败: {str(e)}")
        raise HTTPException(status_code=400, detail=f"PDF解析失败: {e}")

async def download_pdf(url: str) -> bytes:
    """下载PDF文件"""
    try:
        # 确保URL是字符串
        url_str = str(url)
        
        # 验证URL协议
        if not url_str.startswith(("http://", "https://")):
            raise ValueError("无效的URL协议")
        
        # 设置超时（不需要limits对象）
        timeout = httpx.Timeout(60.0)
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url_str)
            response.raise_for_status()
            
            # 验证内容类型
            content_type = response.headers.get("content-type", "").lower()
            if "pdf" not in content_type:
                # 对于中文URL的服务端，有时会返回HTML错误页面
                if "text/html" in content_type:
                    raise ValueError("URL指向的是一个HTML页面，而不是PDF文件")
                else:
                    raise ValueError(f"URL指向的文件不是PDF格式 (Content-Type: {content_type})")
                
            # 检查文件大小
            max_size = 55 * 1024 * 1024  # 50MB
            if len(response.content) > max_size:
                raise ValueError(f"PDF文件过大 (大小: {len(response.content)//1024}KB, 最大允许: {max_size//1024}KB)")
                
            return response.content
    except Exception as e:
        logger.error(f"PDF下载错误: {str(e)}")
        raise HTTPException(status_code=400, detail=f"PDF下载失败：{e}")

# 真实的元宝API调用函数
SecretId = os.environ.get('TENCENTCLOUD_SECRET_ID')
SecretKey = os.environ.get('TENCENTCLOUD_SECRET_KEY')
HUNYUAN_CLIENT=None
import threading
HUNYUAN_CLIENT_LOCK = threading.Lock()

def call_yuanbao(prompt: str) -> str:
    """调用元宝大模型API"""
    global HUNYUAN_CLIENT
    try:
        #使用全局客户端（线程安全）
        if HUNYUAN_CLIENT is None:
            with HUNYUAN_CLIENT_LOCK:
                if HUNYUAN_CLIENT is None:
                    # 创建凭证对象
                    cred = credential.Credential(SecretId, SecretKey)
                    # 配置HTTP参数
                    httpProfile = HttpProfile()
                    httpProfile.endpoint = "hunyuan.tencentcloudapi.com"
                    httpProfile.reqTimeout = 300  # 设置超时时间为300秒
                    # 配置客户端Profile
                    clientProfile = ClientProfile()
                    clientProfile.httpProfile = httpProfile
                    # 创建客户端
                    HUNYUAN_CLIENT= hunyuan_client.HunyuanClient(
                        cred, "ap-guangzhou", clientProfile
                    )
        # 创建请求对象
        req = models.ChatCompletionsRequest()
        req.Model="hunyuan-turbos-longtext-128k-20250325"
        req.Messages=[{"Role": "user", "Content": prompt}]
        req.Stream=False
        
        start_time=time.time()
        # 发送请求
        resp = HUNYUAN_CLIENT.ChatCompletions(req)
        elapsed=time.time()-start_time

        #保存返回
        

        # 返回内容,处理响应
        if resp and hasattr(resp, 'Choices') and resp.Choices:
            logger.info(f"调用成功| 耗时{elapsed:.2f}")
            with open(f"调用.txt", "a", encoding="utf-8") as f:
                resp_dict=resp.Id
                f.write(json.dumps(resp_dict, ensure_ascii=False) + "\n")  # 写入文件
                f.write(json.dumps(resp.Choices[0].Message.Content, ensure_ascii=False) + "\n")
            return resp.Choices[0].Message.Content
        return "无响应内容"
        
    except TencentCloudSDKException as err:
        logger.error(f"元宝API调用失败: {err}")
        return f"元宝API调用失败: {err}"
    except Exception as e:
        logger.error(f"元宝调用异常: {str(e)}")
        return f"元宝调用异常: {str(e)}"

async def process_pdf_url(pdf_url: HttpUrl, item_id: str) -> dict:
    """处理单个PDF URL"""
    start_time = time.time()
    # 将HttpUrl转换为字符串
    url_str = convert_httpurl_to_string(pdf_url)
    try:
        # 获取信号量许可（控制并发）
        async with semaphore:
            logger.info(f"[{item_id}] 开始处理PDF: {url_str}")
            # 1.下载PDF(内存中暂存)
            pdf_bytes = await download_pdf(url_str)
            logger.info(f"[{item_id}] PDF下载成功 | 文件大小: {len(pdf_bytes)//1024}KB")
            # 2.提取原始文件名和文本
            filename = extract_filename_from_url(url_str)
            pdf_text = extract_pdf_text(pdf_bytes, filename)
            logger.info(f"[{item_id}] 文本提取完成 | 字符数: {len(pdf_text)}")
            #3.释放PDF二进制数据
            del pdf_bytes

            # 4.构造提示
            prompt = build_audit_prompt(pdf_text)
            logger.debug(f"[{item_id}] 提示词: {prompt[:100]}...")
            
            # 5.调用混元大模型
            logger.info(f"[{item_id}] 调用元宝API...")
            result = await asyncio.to_thread(call_yuanbao,prompt)
            logger.info(f"[{item_id}] 👑👑👑元宝API调用完成 | 结果长度: {len(result)}")
            # 6.立即释放文本数据
            del pdf_text,prompt
            processing_time=round(time.time() - start_time, 2)
            
            # 7.更新数据库中的记录
            conn = sqlite3.connect("audit.db")
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE audit_items 
                SET status = 'success', result = ?, error_message = NULL, processing_time = ?
                WHERE item_id = ?
            """, (json.dumps(result, ensure_ascii=False), processing_time, item_id))
            conn.commit()
            conn.close()

            return {
                "item_id": item_id,
                "pdf_url": url_str,
                "status": "success",
                "processing_time": processing_time,
                "result": result
            }
    
    except Exception as e:
        processing_time = time.time() - start_time
        # 确保错误时也释放资源
        if 'pdf_bytes' in locals(): del pdf_bytes
        if 'pdf_text' in locals(): del pdf_text
        conn = sqlite3.connect("audit.db")
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE audit_items 
            SET status = 'error', result = NULL, error_message = ?, processing_time = ?
            WHERE item_id = ?
        """, (str(e), processing_time, item_id))
        conn.commit()
        conn.close()

        return {
            "item_id": item_id,
            "pdf_url": url_str,
            "status": "error",
            "processing_time": processing_time,
            "error_message": str(e)
        }


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 允许所有来源，生产环境应限制为具体域名
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有HTTP方法
    allow_headers=["*"],  # 允许所有头
)

@app.get("/audit")
async def get_audit_info():
    return {
        "status": "success",
        "message": "PDF审查API正常运行",
        "version": "1.0.0",
        "endpoint": "/audit",
        "supported_methods": ["GET", "POST"],
        "usage": "POST请求需传入urls列表进行pdf审查，最多地址数量为50，最大并发为5"
    }


async def process_items(audit_items: List[AuditItem]):
    """处理多个PDF项目"""
    tasks = []
    for item in audit_items:
        task = asyncio.create_task(
            process_pdf_url(item.url, item.id)
        )
        tasks.append(task)
    # 等待所有任务完成并返回结果
    results = await asyncio.gather(*tasks)
    return results


@app.post("/audit")
async def process_audit_request(audit_request: AuditRequest):
    """处理审查请求"""
    MAX_ITEMS_PER_BATCH = 5
    items = list(audit_request)
    if not items:
        raise HTTPException(status_code=400, detail="No items provided")
    
    # 先将所有任务插入数据库，状态设为"processing"
    conn = sqlite3.connect("audit.db")
    cursor = conn.cursor()
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
    for item in items:
        url_str = convert_httpurl_to_string(item.url)
        cursor.execute("""
            INSERT OR REPLACE INTO audit_items 
            (item_id, pdf_url, status, create_time) 
            VALUES (?, ?, 'processing', ?)
        """, (item.id, url_str, current_time))
    
    conn.commit()
    conn.close()
    
    # 然后异步处理这些任务
    batches = [items[i:i + MAX_ITEMS_PER_BATCH] for i in range(0, len(items), MAX_ITEMS_PER_BATCH)]
    tasks = []

    for batch_items in batches:
        task = asyncio.create_task(process_items(batch_items))
        tasks.append(task)

    return{"status":"success", "message": "审查任务已创建，可以通过GET /audit/{item_id}查询状态"}

@app.get("/audit/{item_id}")
def get_item_result(item_id: str):
    """获取单个项目的处理结果"""
    conn = sqlite3.connect("audit.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT item_id, pdf_url, status, result, error_message, processing_time, create_time
        FROM audit_items
        WHERE item_id = ?
    """, (item_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"item_id": item_id, "status": "failure"}

    item_id, pdf_url, status, result, error_message, processing_time, create_time = row
    
    return {
        "item_id": item_id,
        "pdf_url": pdf_url,
        "status": status,
        "result": json.loads(result) if result and status == "success" else None,
        "error_message": error_message,
        "processing_time": processing_time,
        "create_time": create_time
    }

def init_db():
    conn = sqlite3.connect("audit.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_items (
            item_id TEXT PRIMARY KEY,
            pdf_url TEXT,
            status TEXT,
            result TEXT,
            error_message TEXT,
            processing_time REAL,
            create_time TEXT
        )
    """)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    import uvicorn
    init_db()
    uvicorn.run("main:app", host="0.0.0.0", port=8001,reload=True)
