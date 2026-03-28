"""
Skills 威胁分析引擎 - 主入口

提供CLI命令行接口和主要功能入口。
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional, List

import click
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))


console = Console()


def get_mongodb_storage():
    """获取MongoDB存储实例"""
    from src.storage.mongodb import MongoDBStorage

    return MongoDBStorage()


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """配置日志"""
    logger.remove()

    # 控制台输出
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    )

    # 文件输出
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_file,
            level=log_level,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
            rotation="10 MB",
            retention="7 days",
        )


@click.group()
@click.option("--log-level", default="INFO", help="日志级别")
@click.option("--log-file", default=None, help="日志文件路径")
@click.pass_context
def cli(ctx, log_level: str, log_file: Optional[str]):
    """SkillScan - Skills 威胁分析引擎"""
    setup_logging(log_level, log_file)
    ctx.ensure_object(dict)
    ctx.obj["log_level"] = log_level


@cli.command()
@click.option("--path", "-p", required=True, help="本地目录路径")
@click.option("--limit", "-l", default=None, type=int, help="最大扫描数量")
@click.option("--output", "-o", default=None, help="输出文件路径")
@click.option(
    "--format",
    "fmt",
    default="json",
    type=click.Choice(["json", "markdown", "html"]),
    help="输出格式",
)
@click.option("--skip-llm", is_flag=True, help="跳过LLM分析")
@click.option("--no-db", is_flag=True, help="不保存到MongoDB")
@click.pass_context
def scan_local(
    ctx,
    path: str,
    limit: Optional[int],
    output: Optional[str],
    fmt: str,
    skip_llm: bool,
    no_db: bool,
):
    """扫描本地目录中的技能文件"""
    asyncio.run(_scan_local_async(path, limit, output, fmt, skip_llm, no_db))


async def _scan_local_async(
    path: str,
    limit: Optional[int],
    output: Optional[str],
    fmt: str,
    skip_llm: bool,
    no_db: bool,
):
    """异步扫描本地目录"""
    from src.core.scan_engine import ScanEngine

    console.print(f"[bold blue]SkillScan - Local Scan[/bold blue]")
    console.print(f"Path: {path}")
    console.print()

    # 初始化扫描引擎
    mongodb = None if no_db else get_mongodb_storage()
    engine = ScanEngine(mongodb=mongodb)

    if mongodb:
        await engine.initialize()
        console.print("[green]MongoDB connected[/green]")

    console.print()

    # 执行扫描
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning skills...", total=None)
        result = await engine.scan_local_directory(
            path=path,
            limit=limit,
            skip_llm=skip_llm,
            save_to_db=not no_db,
        )
        progress.update(task, completed=True)

    # 显示结果
    scan_results = result.get("scan_results", [])
    _display_results(scan_results)

    # 显示统计信息
    stats = result.get("statistics", {})
    if stats:
        console.print()
        console.print(f"[bold]Statistics:[/bold]")
        console.print(f"  Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        console.print(f"  Vulnerable Skills: {stats.get('vulnerable_percentage', 0):.1f}%")

    # 保存报告
    if output:
        from src.reporters.report_generator import ReportGenerator

        report_gen = ReportGenerator()

        if fmt == "json":
            content = report_gen.generate_json_report(result)
        elif fmt == "markdown":
            content = report_gen.generate_markdown_report(result)
        else:
            content = report_gen.generate_html_report(result)

        Path(output).write_text(content, encoding="utf-8")
        console.print(f"\n[green]Report saved to {output}[/green]")

    # 关闭连接
    await engine.shutdown()


def _display_results(results: List[dict]):
    """显示分析结果"""
    table = Table(title="Scan Results")
    table.add_column("Skill", style="cyan")
    table.add_column("Risk Level", style="bold")
    table.add_column("Risk Score", justify="right")
    table.add_column("Vulnerabilities", justify="right")
    table.add_column("Categories")

    for result in results:
        risk_color = {
            "safe": "green",
            "warning": "yellow",
            "dangerous": "red",
            "malicious": "bold red",
        }.get(result.get("risk_level", "safe"), "white")

        vuln_count = result.get("vulnerability_count", {})
        categories = ", ".join(vuln_count.keys()) if vuln_count else "-"

        table.add_row(
            result.get("name", "Unknown")[:30],
            f"[{risk_color}]{result.get('risk_level', 'safe').upper()}[/{risk_color}]",
            f"{result.get('risk_score', 0.0):.2f}",
            str(sum(vuln_count.values())),
            categories,
        )

    console.print(table)

    # 统计摘要
    total = len(results)
    malicious = sum(1 for r in results if r.get("risk_level") == "malicious")
    dangerous = sum(1 for r in results if r.get("risk_level") == "dangerous")
    warning = sum(1 for r in results if r.get("risk_level") == "warning")
    safe = sum(1 for r in results if r.get("risk_level") == "safe")

    console.print()
    console.print(f"[bold]Summary:[/bold]")
    console.print(f"  Total: {total}")
    console.print(f"  Safe: [green]{safe}[/green]")
    console.print(f"  Warning: [yellow]{warning}[/yellow]")
    console.print(f"  Dangerous: [red]{dangerous}[/red]")
    console.print(f"  Malicious: [bold red]{malicious}[/bold red]")


@cli.command()
@click.option("--url", "-u", required=True, help="要扫描的URL")
@click.option("--output", "-o", default=None, help="输出文件路径")
@click.option("--skip-llm", is_flag=True, help="跳过LLM分析")
@click.option("--no-db", is_flag=True, help="不保存到MongoDB")
def scan_url(url: str, output: Optional[str], skip_llm: bool, no_db: bool):
    """扫描URL中的技能文件"""
    asyncio.run(_scan_url_async(url, output, skip_llm, no_db))


async def _scan_url_async(
    url: str,
    output: Optional[str],
    skip_llm: bool,
    no_db: bool,
):
    """异步扫描URL"""
    from src.collectors.network_collector import NetworkCollector
    from src.core.scan_engine import ScanEngine

    console.print(f"[bold blue]SkillScan - URL Scan[/bold blue]")
    console.print(f"URL: {url}")
    console.print()

    # 初始化扫描引擎
    mongodb = None if no_db else get_mongodb_storage()
    engine = ScanEngine(mongodb=mongodb)

    if mongodb:
        await engine.initialize()
        console.print("[green]MongoDB connected[/green]")

    # 爬取URL
    collector = NetworkCollector()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching URL...", total=None)
        skill = await collector.crawl_url(url)
        progress.update(task, completed=True)

    if not skill:
        console.print("[red]Failed to fetch skill from URL[/red]")
        await engine.shutdown()
        return

    console.print(f"Found skill: [bold]{skill.name}[/bold]")
    console.print()

    # 分析技能
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing skill...", total=None)

        # 使用扫描引擎的内部方法
        result = await engine._analyze_and_store_skill(
            skill=skill,
            skip_llm=skip_llm,
            save_to_db=not no_db,
        )
        progress.update(task, completed=True)

    # 显示结果
    _display_results([result])

    # 保存报告
    if output:
        from src.reporters.report_generator import ReportGenerator

        report_gen = ReportGenerator()

        content = report_gen.generate_json_report(result)
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"\n[green]Report saved to {output}[/green]")

    await collector.close()
    await engine.shutdown()


@cli.command()
@click.option("--platforms", "-p", default="clawhub,smithery,skillssh", help="平台列表（逗号分隔）")
@click.option("--limit", "-l", default=100, type=int, help="每个平台最大爬取数量")
@click.option("--output", "-o", default=None, help="输出文件路径")
@click.option("--skip-llm", is_flag=True, help="跳过LLM分析")
@click.option("--no-db", is_flag=True, help="不保存到MongoDB")
def scan_network(platforms: str, limit: int, output: Optional[str], skip_llm: bool, no_db: bool):
    """从网络平台爬取并扫描技能文件"""
    asyncio.run(_scan_network_async(platforms, limit, output, skip_llm, no_db))


async def _scan_network_async(
    platforms: str,
    limit: int,
    output: Optional[str],
    skip_llm: bool,
    no_db: bool,
):
    """异步网络爬取扫描"""
    from src.collectors.network_collector import NetworkCollector
    from src.core.scan_engine import ScanEngine

    platform_list = [p.strip() for p in platforms.split(",")]

    console.print(f"[bold blue]SkillScan - Network Scan[/bold blue]")
    console.print(f"Platforms: {', '.join(platform_list)}")
    console.print(f"Limit per platform: {limit}")
    console.print()

    # 初始化扫描引擎
    mongodb = None if no_db else get_mongodb_storage()
    engine = ScanEngine(mongodb=mongodb)

    if mongodb:
        await engine.initialize()
        console.print("[green]MongoDB connected[/green]")

    # 爬取技能
    collector = NetworkCollector(platforms=platform_list)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting skills from platforms...", total=None)
        skills = await collector.collect(limit=limit)
        progress.update(task, completed=True)

    console.print(f"Found [bold]{len(skills)}[/bold] skills")
    console.print()

    if not skills:
        console.print("[yellow]No skills found.[/yellow]")
        await collector.close()
        await engine.shutdown()
        return

    # 分析技能
    results = []
    all_vulnerabilities = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing skills...", total=len(skills))

        for skill in skills:
            progress.update(task, description=f"Analyzing {skill.name}...")
            result = await engine._analyze_and_store_skill(
                skill=skill,
                skip_llm=skip_llm,
                save_to_db=not no_db,
            )
            results.append(result)
            all_vulnerabilities.extend(result.get("vulnerabilities", []))
            progress.advance(task)

    # 显示结果
    _display_results(results)

    # 保存报告
    if output:
        from src.reporters.report_generator import ReportGenerator

        report_gen = ReportGenerator()

        result = {
            "scan_results": results,
            "vulnerabilities": all_vulnerabilities,
            "statistics": engine._calculate_statistics(results, all_vulnerabilities),
        }

        content = report_gen.generate_json_report(result)
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"\n[green]Report saved to {output}[/green]")

    await collector.close()
    await engine.shutdown()


@cli.command()
@click.option("--host", default="0.0.0.0", help="API服务器主机")
@click.option("--port", default=8000, help="API服务器端口")
@click.option("--reload", is_flag=True, help="启用自动重载")
def serve(host: str, port: int, reload: bool):
    """启动API服务器"""
    import uvicorn

    console.print(f"[bold blue]SkillScan API Server[/bold blue]")
    console.print(f"Starting server at http://{host}:{port}")
    console.print(f"API Docs: http://{host}:{port}/api/docs")
    console.print()

    uvicorn.run(
        "src.api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@cli.command()
@click.option("--path", "-p", required=True, help="技能文件路径")
def analyze(path: str):
    """分析单个技能文件"""
    asyncio.run(_analyze_single_async(path))


async def _analyze_single_async(path: str):
    """异步分析单个技能文件"""
    from src.collectors.local_collector import LocalCollector
    from src.analyzers.hybrid_analyzer import HybridAnalyzer
    from src.reporters.report_generator import ReportGenerator

    collector = LocalCollector()
    skills = await collector.scan_path(path)

    if not skills:
        console.print("[red]No valid skill found at specified path[/red]")
        return

    skill = skills[0]
    console.print(f"[bold]Analyzing: {skill.name}[/bold]")
    console.print()

    analyzer = HybridAnalyzer()
    result = await analyzer.analyze(
        skill_md=skill.content,
        scripts=skill.scripts,
        skill_id=skill.content_hash[:16],
        skip_llm=False,
    )

    # 显示结果
    report_gen = ReportGenerator()
    markdown_report = report_gen.generate_markdown_report(result)
    console.print(markdown_report)


@cli.command()
def version():
    """显示版本信息"""
    from src import __version__

    console.print(f"SkillScan v{__version__}")


@cli.command()
def db_stats():
    """显示MongoDB数据库统计"""
    asyncio.run(_db_stats_async())


async def _db_stats_async():
    """异步获取数据库统计"""
    from src.core.scan_engine import ScanEngine

    mongodb = get_mongodb_storage()
    engine = ScanEngine(mongodb=mongodb)

    await engine.initialize()

    stats = await engine.get_scan_statistics()

    if "error" in stats:
        console.print(f"[red]Error: {stats['error']}[/red]")
        await engine.shutdown()
        return

    # 显示技能统计
    skill_stats = stats.get("skills", {})
    if skill_stats:
        console.print("[bold blue]Database Statistics[/bold blue]")
        console.print()

        table = Table(title="Skills Overview")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")

        table.add_row("Total Skills", str(skill_stats.get("total", 0)))
        table.add_row("Scanned", str(skill_stats.get("scanned", 0)))
        table.add_row("Pending", str(skill_stats.get("pending", 0)))

        console.print(table)

    # 显示风险分布
    risk_dist = stats.get("risk_distribution", {})
    if risk_dist:
        console.print()

        table = Table(title="Risk Distribution")
        table.add_column("Risk Level", style="cyan")
        table.add_column("Count", justify="right")

        risk_colors = {
            "safe": "green",
            "warning": "yellow",
            "dangerous": "red",
            "malicious": "bold red",
        }

        for level, count in risk_dist.items():
            color = risk_colors.get(level, "white")
            table.add_row(f"[{color}]{level.upper()}[/{color}]", str(count))

        console.print(table)

    await engine.shutdown()


@cli.command()
@click.option("--language", "-l", default=None, help="语言筛选")
def list_rules(language: Optional[str]):
    """列出检测规则"""
    from src.models.configuration import DEFAULT_DETECTION_RULES

    rules = DEFAULT_DETECTION_RULES
    if language:
        rules = [r for r in rules if r.get("language") == language or r.get("language") == "all"]

    table = Table(title=f"Detection Rules ({len(rules)} total)")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Category")
    table.add_column("Pattern")
    table.add_column("Severity")
    table.add_column("Language")

    for rule in rules:
        table.add_row(
            rule.get("rule_id", ""),
            rule.get("category", ""),
            rule.get("pattern_code", ""),
            rule.get("severity", ""),
            rule.get("language", "all"),
        )

    console.print(table)


def main():
    """主入口"""
    cli()


if __name__ == "__main__":
    main()
