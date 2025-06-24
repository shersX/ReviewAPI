import os,re,io,time,uuid,json,httpx,asyncio,logging
from pathlib import Path
from pypdf import PdfReader
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
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

# 创建临时目录
TEMP_DIR = Path("temp")
TEMP_DIR.mkdir(exist_ok=True)

# 并发控制
MAX_CONCURRENT = 5
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

# 固定的50条审查规则
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
    "14. 项目名称是否与神经或肿瘤药物研发有关",
    "15. 项目名称是否逻辑正确，是否清晰明确",
    "16. 项目名称是否与研究内容吻合",
    "17. 项目摘要是否在800字以内",
    "18. 项目摘要是否包含1）研究背景+待解决的问题 2）前期结果+假说+内容 3）研究意义",
    "19. 立项依据是否包含1）课题背景2）研究现状3）当前亟待解决的问题",
    "20. 立项依据是否结合对应文献和前期结果",
    "21. 立项依据部分，引用文献对应的内容是否真实",
    "22. 参考文献是否在30-50篇之间",
    "23. 参考文献是否保持格式统一",
    "24. 参考文献中是否包含近5年的研究，引用近5年研究的数量是否合适",
    "25. 立项依据部分是否有子标题，是否有下划线/加粗等标注突出重点",
    "26. 立项依据是否附有图文",
    "27. 立项依据部分所有文字是否超过4000字",
    "28. 研究内容是否分阶段、分方面展示",
    "29. 研究方案中的样本量是否合理",
    "30. 研究方案中的样本量是否有对应的理论依据",
    "31. 拟采取的研究方案和可行性分析是否分点分节说明",
    "32. 是否有技术路线图",
    "33. 技术路线图是否清晰",
    "34. 研究内容、研究目标以及拟解决的关键科学问题部分所有文字是否超过4000字",
    "35. 项目研究的内容在同领域中，是否已经存在很多已发表的研究成果",
    "36. 项目是否具备转化价值",
    "37. 项目能否解决当下该研究领域内的痛点难点",
    "38. 项目是否有区别于其他同类研究的亮点",
    "39. 项目研究计划是否分时间节点或分阶段展示",
    "40. 项目产出的成果是否可衡量",
    "41. 项目产出的成果是否有含金量",
    "42. 项目是否可以在2年内达到预期成果",
    "43. 申请人及团队的研究领域与课题研究方向是否匹配",
    "44. 申请人及团队所在单位是否具备完成项目所需要的技术条件",
    "45. 申请人团队成员组成是否合理",
    "46. 申请人及团队的分工是否清晰，细化",
    "47. 申请人简介中，申请人发表的文章是否标注影响因子",
    "48. 申请人简介中，申请人发表的文章是否体现本人排序",
    "49. 申请人简介中，申请人发表的文章是否与本项目研究内容相关",
    "50. 项目经费预算中，参照国自然同类项目，申请人填写的是否合理"
]

# 请求模型
class AuditRequest(BaseModel):
    single_url: Optional[HttpUrl] = None
    batch_urls: Optional[List[HttpUrl]] = None
    callback_url: Optional[HttpUrl] = None

# 响应模型
class AuditItemResult(BaseModel):
    request_id: str
    pdf_url: str
    status: str
    processing_time: float
    result: Optional[str] = None
    error_message: Optional[str] = None

class AuditResponse(BaseModel):
    batch_id: str
    status: str
    result: Optional[Dict[str, Any]] = None

app = FastAPI()

# 辅助函数
def generate_id() -> str:
    """生成唯一ID"""
    return uuid.uuid4().hex[:8]

def convert_httpurl_to_string(url) -> str:
    """将 HttpUrl 对象转换为字符串"""
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
    """构造审查提示"""
    rule_text = "\n".join(FIXED_AUDIT_RULES)
    
    # 添加外部数据需求的说明
    external_data_rules = [1, 21, 35, 36, 37, 38, 42, 50]
    external_rule_texts = "\n".join([
        f"规则 {num}: {FIXED_AUDIT_RULES[num-1].split('. ', 1)[1]}"
        for num in external_data_rules
    ])
    extra_instruction = (
        "\n\n注意：以下规则因为依赖外部数据，不需要根据PDF内容判断，"
        "请直接赋值为 `TBD`，且不需要提供理由：\n"
        f"{external_rule_texts}\n"
    )
    
    return f"""
你是一个形式审查员。请根据以下50条规则，对这份PDF内容进行逐条审查。

输出格式要求：
- 以json形式输出；
- 每条规则对应三列："规则内容"、"评估结果（可行/不可行/TBD）"、"理由（如有）"。

评审规则如下：
{rule_text}
{extra_instruction}

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
        text_content = "\n".join([page.extract_text() or "" for page in reader.pages])
        
        # 保存提取的文本到临时文件
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(text_content)
        logger.info(f"📄 已保存提取文本到临时文件: {temp_file}")
        
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
            max_size = 50 * 1024 * 1024  # 50MB
            if len(response.content) > max_size:
                raise ValueError(f"PDF文件过大 (大小: {len(response.content)//1024}KB, 最大允许: {max_size//1024}KB)")
                
            return response.content
    except httpx.HTTPError as e:
        logger.error(f"PDF下载失败: {str(e)}")
        raise HTTPException(status_code=400, detail=f"PDF下载失败: {e}")
    except Exception as e:
        logger.error(f"下载错误: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

# 真实的元宝API调用函数
SecretId = os.environ.get('TENCENTCLOUD_SECRET_ID')
SecretKey = os.environ.get('TENCENTCLOUD_SECRET_KEY')

def call_yuanbao(prompt: str) -> str:
    """调用元宝大模型API"""
    try:
        # 创建凭证对象
        cred = credential.Credential(SecretId, SecretKey)
        
        # 配置HTTP参数
        httpProfile = HttpProfile()
        httpProfile.endpoint = "hunyuan.tencentcloudapi.com"
        httpProfile.reqTimeout = 1800  # 设置超时时间为180秒
        
        # 配置客户端Profile
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        
        # 创建客户端
        client = hunyuan_client.HunyuanClient(cred, "ap-guangzhou", clientProfile)
        
        # 创建请求对象
        req = models.ChatCompletionsRequest()
        params = {
            "Model": "hunyuan-turbos-latest",
            "Messages": [
                {
                    "Role": "user",
                    "Content": prompt
                }
            ],
            "Stream": False
        }
        req.from_json_string(json.dumps(params))
        
        # 发送请求
        resp = client.ChatCompletions(req)
        
        # 返回内容
        if hasattr(resp, 'Choices') and resp.Choices:
            return resp.Choices[0].Message.Content
        return "无响应内容"

    except TencentCloudSDKException as err:
        logger.error(f"元宝API调用失败: {err}")
        return f"元宝API调用失败: {err}"
    except Exception as e:
        logger.error(f"元宝调用异常: {str(e)}")
        return f"元宝调用异常: {str(e)}"

async def process_pdf_url(pdf_url: HttpUrl) -> dict:
    """处理单个PDF URL"""
    request_id = generate_id()
    start_time = time.time()
    
    try:
        # 获取信号量许可（控制并发）
        async with semaphore:
            # 将HttpUrl转换为字符串
            url_str = convert_httpurl_to_string(pdf_url)
            logger.info(f"[{request_id}] 开始处理PDF: {url_str}")
            
            # 下载PDF
            pdf_bytes = await download_pdf(url_str)
            logger.info(f"[{request_id}] PDF下载成功 | 文件大小: {len(pdf_bytes)//1024}KB")
            
            # 提取原始文件名
            filename = extract_filename_from_url(url_str)
            
            # 提取文本
            pdf_text = extract_pdf_text(pdf_bytes, filename)
            logger.info(f"[{request_id}] 文本提取完成 | 字符数: {len(pdf_text)}")
            
            # 构造提示
            prompt = build_audit_prompt(pdf_text)
            logger.debug(f"[{request_id}] 提示词: {prompt[:100]}...")
            
            # 调用模型 - 使用真实API
            logger.info(f"[{request_id}] 调用元宝API...")
            #将同步函数放入线程池窒执行
            result = await asyncio.to_thread(call_yuanbao,prompt)
            logger.info(f"[{request_id}] 元宝API调用完成 | 结果长度: {len(result)}")
            
            return {
                "request_id": request_id,
                "pdf_url": url_str,
                "status": "success",
                "processing_time": time.time() - start_time,
                "result": result
            }
    
    except Exception as e:
        return {
            "request_id": request_id,
            "pdf_url": convert_httpurl_to_string(pdf_url),
            "status": "error",
            "processing_time": time.time() - start_time,
            "error_message": str(e)
        }

async def process_batch_sync(urls: List[HttpUrl]) -> List[dict]:
    """同步批量处理"""
    tasks = [process_pdf_url(url) for url in urls]
    return await asyncio.gather(*tasks)

async def process_batch_async(batch_id: str, urls: List[HttpUrl], callback_url: str):
    """异步批量处理并发送回调"""
    try:
        logger.info(f"[{batch_id}] 开始异步批量处理 | URL数量: {len(urls)}")
        results = await process_batch_sync(urls)
        
        # 准备回调数据
        callback_data = {
            "batch_id": batch_id,
            "status": "completed",
            "result": {
                "total": len(urls),
                "completed": len(results),
                "successful": sum(1 for r in results if r["status"] == "success"),
                "failed": sum(1 for r in results if r["status"] != "success"),
                "items": results
            }
        }
        
        # 发送回调
        async with httpx.AsyncClient() as client:
            response = await client.post(convert_httpurl_to_string(callback_url), json=callback_data, timeout=10)
            response.raise_for_status()
            logger.info(f"[{batch_id}] 回调发送成功: {callback_url}")
    
    except Exception as e:
        logger.error(f"[{batch_id}] 异步处理或回调失败: {str(e)}")

@app.post("/audit", response_model=AuditResponse)
async def audit_endpoint(request: AuditRequest):
    """统一PDF审查端点"""
    # 确定要处理的URL列表
    urls = []
    
    if request.batch_urls:
        urls = request.batch_urls
        if len(urls) > 50:
            raise HTTPException(status_code=400, detail="单次批量请求最多支持50个URL")
    elif request.single_url:
        urls = [request.single_url]
    else:
        raise HTTPException(status_code=400, detail="没有提供有效的PDF URL")
    
    # 创建批次ID
    batch_id = generate_id()
    logger.info(f"批次 {batch_id} 开始处理 | URL数量: {len(urls)}")
    
    # 处理单个URL（同步返回）
    if len(urls) == 1 and not request.callback_url:
        result = await process_pdf_url(urls[0])
        
        return AuditResponse(
            batch_id=batch_id,
            status="completed",
            result={
                "total": 1,
                "completed": 1,
                "successful": 1 if result["status"] == "success" else 0,
                "failed": 1 if result["status"] != "success" else 0,
                "items": [result]
            }
        )
    
    # 处理批量请求（使用回调）
    if request.callback_url:
        # 异步处理
        callback_str = convert_httpurl_to_string(request.callback_url)
        asyncio.create_task(process_batch_async(batch_id, urls, callback_str))
        return AuditResponse(
            batch_id=batch_id,
            status="processing"
        )
    
    # 处理批量请求（同步返回）
    results = await process_batch_sync(urls)
    
    return AuditResponse(
        batch_id=batch_id,
        status="completed",
        result={
            "total": len(urls),
            "completed": len(results),
            "successful": sum(1 for r in results if r["status"] == "success"),
            "failed": sum(1 for r in results if r["status"] != "success"),
            "items": results
        }
    )

@app.on_event("startup")
async def startup_event():
    """应用启动时清理旧临时文件"""
    logger.info("🔧 应用启动，清理旧临时文件...")
    now = time.time()
    for file in TEMP_DIR.glob("*.md"):
        if file.stat().st_mtime < now - 2 * 86400:  # 7天
            try:
                file.unlink()
                logger.info(f"清理旧临时文件: {file}")
            except Exception as e:
                logger.warning(f"清理文件失败: {file} - {str(e)}")
    logger.info("🔧 临时文件清理完成")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)