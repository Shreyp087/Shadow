from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from uuid import UUID
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models.attack_result import AttackResult
from models.attack_run import AttackRun
from models.enums import RiskCategory
from models.target_system import TargetSystem
from models.trust_ledger_entry import TrustLedgerEntry
from services.trust_ledger import TrustLedger


@dataclass(slots=True)
class AuditReportSnapshot:
    attack_run: AttackRun
    target_system: TargetSystem
    results: list[AttackResult]
    high_critical_results: list[AttackResult]
    top_critical_results: list[AttackResult]
    risk_distribution: dict[RiskCategory, int]
    ledger_entries: list[TrustLedgerEntry]
    ledger_entry_statuses: dict[UUID, bool]


class ReportGenerator:
    async def generate_audit_report(self, attack_run_id: UUID, db_session: AsyncSession) -> bytes:
        snapshot = await self._load_snapshot(attack_run_id, db_session)
        return await asyncio.to_thread(self._build_pdf, snapshot)

    async def _load_snapshot(self, attack_run_id: UUID, db_session: AsyncSession) -> AuditReportSnapshot:
        run_statement = (
            select(AttackRun)
            .options(selectinload(AttackRun.target_system))
            .where(AttackRun.id == attack_run_id)
        )
        attack_run = await db_session.scalar(run_statement)
        if attack_run is None:
            raise ValueError(f"Attack run {attack_run_id} was not found")
        if attack_run.target_system is None:
            raise ValueError(f"Target system for attack run {attack_run_id} was not found")

        results_statement = (
            select(AttackResult)
            .options(
                selectinload(AttackResult.attack_vector),
                selectinload(AttackResult.trust_ledger_entries),
            )
            .where(AttackResult.attack_run_id == attack_run.id)
            .order_by(AttackResult.executed_at.asc(), AttackResult.id.asc())
        )
        result_rows = await db_session.execute(results_statement)
        results = list(result_rows.scalars().all())

        high_critical_results = [
            result for result in results if result.risk_category in {RiskCategory.HIGH, RiskCategory.CRITICAL}
        ]
        top_critical_results = sorted(
            (result for result in results if result.risk_category == RiskCategory.CRITICAL),
            key=lambda item: (item.risk_score, item.executed_at),
            reverse=True,
        )[:3]
        risk_distribution = {
            category: sum(1 for result in results if result.risk_category == category)
            for category in RiskCategory
        }

        trust_ledger = TrustLedger(db_session)
        ledger_entries = await trust_ledger.get_entries(attack_run.id)
        ledger_entry_statuses = await trust_ledger.get_entry_verification_statuses([entry.id for entry in ledger_entries])

        return AuditReportSnapshot(
            attack_run=attack_run,
            target_system=attack_run.target_system,
            results=results,
            high_critical_results=high_critical_results,
            top_critical_results=top_critical_results,
            risk_distribution=risk_distribution,
            ledger_entries=ledger_entries,
            ledger_entry_statuses=ledger_entry_statuses,
        )

    def _build_pdf(self, snapshot: AuditReportSnapshot) -> bytes:
        buffer = BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=landscape(letter),
            topMargin=0.65 * inch,
            bottomMargin=0.65 * inch,
            leftMargin=0.55 * inch,
            rightMargin=0.55 * inch,
            title=f"ShadowLedger Security Audit Report - {snapshot.attack_run.id}",
            author="ShadowLedger",
        )
        styles = self._build_styles()
        story: list[Any] = []

        story.extend(self._build_cover_page(snapshot, styles))
        story.extend(self._build_executive_summary(snapshot, styles))
        story.extend(self._build_attack_results_section(snapshot, styles))
        story.extend(self._build_trust_ledger_section(snapshot, styles))

        document.build(
            story,
            onFirstPage=lambda canvas, doc: self._draw_footer(canvas, doc, snapshot.attack_run.id),
            onLaterPages=lambda canvas, doc: self._draw_footer(canvas, doc, snapshot.attack_run.id),
        )
        return buffer.getvalue()

    def _build_cover_page(self, snapshot: AuditReportSnapshot, styles: dict[str, ParagraphStyle]) -> list[Any]:
        overall_risk = self._derive_risk_category(snapshot.attack_run.risk_score_avg)
        date_range = self._format_date_range(snapshot)

        return [
            Spacer(1, 0.45 * inch),
            Paragraph("ShadowLedger", styles["brand"]),
            Spacer(1, 0.2 * inch),
            Paragraph("Security Audit Report", styles["report_title"]),
            Spacer(1, 0.25 * inch),
            Paragraph(snapshot.target_system.name, styles["cover_system"]),
            Spacer(1, 0.4 * inch),
            self._build_summary_table(
                [
                    ["Date range", date_range],
                    ["Target type", snapshot.target_system.target_type.value],
                    ["Model", snapshot.target_system.model_name],
                    ["Overall risk rating", overall_risk],
                ],
                styles,
            ),
            Spacer(1, 0.45 * inch),
            Paragraph(
                "Generated by ShadowLedger to document adversarial model testing, evidence preservation, and trust-ledger custody for this attack run.",
                styles["body"],
            ),
            PageBreak(),
        ]

    def _build_executive_summary(
        self,
        snapshot: AuditReportSnapshot,
        styles: dict[str, ParagraphStyle],
    ) -> list[Any]:
        key_findings: list[Any] = []
        if snapshot.top_critical_results:
            for index, result in enumerate(snapshot.top_critical_results, start=1):
                key_findings.append(
                    Paragraph(
                        (
                            f"<b>{index}. {escape(self._result_label(result))}</b> "
                            f"scored {result.risk_score}/100. {escape(self._shorten(result.risk_reason, 180))}"
                        ),
                        styles["body"],
                    )
                )
                key_findings.append(Spacer(1, 0.08 * inch))
        else:
            key_findings.append(Paragraph("No CRITICAL findings were recorded for this run.", styles["body"]))

        distribution_rows = [["Risk Category", "Count"]]
        distribution_rows.extend([[category.value, str(snapshot.risk_distribution[category])] for category in RiskCategory])

        return [
            Paragraph("Executive Summary", styles["section_title"]),
            Spacer(1, 0.12 * inch),
            self._build_summary_table(
                [
                    ["Total attacks", str(snapshot.attack_run.total_attacks)],
                    ["Vulnerabilities found", str(snapshot.attack_run.vulnerabilities_found)],
                    ["Average risk score", self._format_decimal(snapshot.attack_run.risk_score_avg)],
                    ["Overall status", snapshot.attack_run.status.value],
                ],
                styles,
            ),
            Spacer(1, 0.24 * inch),
            Paragraph("Risk distribution", styles["subsection_title"]),
            Spacer(1, 0.08 * inch),
            self._build_small_table(distribution_rows),
            Spacer(1, 0.24 * inch),
            Paragraph("Key findings", styles["subsection_title"]),
            Spacer(1, 0.08 * inch),
            *key_findings,
            PageBreak(),
        ]

    def _build_attack_results_section(
        self,
        snapshot: AuditReportSnapshot,
        styles: dict[str, ParagraphStyle],
    ) -> list[Any]:
        if not snapshot.high_critical_results:
            return [
                Paragraph("High-Risk Attack Results", styles["section_title"]),
                Spacer(1, 0.12 * inch),
                Paragraph("No HIGH or CRITICAL results were recorded for this run.", styles["body"]),
                PageBreak(),
            ]

        summary_rows = [["Category", "Vector", "Score", "Executed At", "Mutation"]]
        for result in snapshot.high_critical_results:
            summary_rows.append(
                [
                    result.risk_category.value,
                    self._result_label(result),
                    str(result.risk_score),
                    self._format_datetime(result.executed_at),
                    "Yes" if result.is_mutation else "No",
                ]
            )

        blocks: list[Any] = [
            Paragraph("High-Risk Attack Results", styles["section_title"]),
            Spacer(1, 0.12 * inch),
            self._build_small_table(summary_rows, column_widths=[1.25 * inch, 2.4 * inch, 0.8 * inch, 1.6 * inch, 0.9 * inch]),
            Spacer(1, 0.24 * inch),
        ]

        for index, result in enumerate(snapshot.high_critical_results, start=1):
            blocks.extend(
                [
                    Paragraph(
                        f"Finding {index}: {escape(self._result_label(result))} ({result.risk_category.value}, score {result.risk_score})",
                        styles["finding_title"],
                    ),
                    Spacer(1, 0.08 * inch),
                    Paragraph(f"<b>Prompt sent</b><br/>{self._escape_multiline(result.prompt_sent)}", styles["detail"]),
                    Spacer(1, 0.08 * inch),
                    Paragraph(
                        f"<b>Response received</b><br/>{self._escape_multiline(result.response_received or 'No response recorded.')}",
                        styles["detail"],
                    ),
                    Spacer(1, 0.08 * inch),
                    Paragraph(f"<b>Risk reason</b><br/>{self._escape_multiline(result.risk_reason)}", styles["detail"]),
                    Spacer(1, 0.18 * inch),
                ]
            )

        blocks.append(PageBreak())
        return blocks

    def _build_trust_ledger_section(
        self,
        snapshot: AuditReportSnapshot,
        styles: dict[str, ParagraphStyle],
    ) -> list[Any]:
        if not snapshot.ledger_entries:
            return [
                Paragraph("Trust Ledger Appendix", styles["section_title"]),
                Spacer(1, 0.12 * inch),
                Paragraph("No trust ledger entries were recorded for this run.", styles["body"]),
            ]

        is_verified = all(snapshot.ledger_entry_statuses.get(entry.id, False) for entry in snapshot.ledger_entries)
        first_broken_entry = next(
            (entry.id for entry in snapshot.ledger_entries if not snapshot.ledger_entry_statuses.get(entry.id, False)),
            None,
        )
        status_text = "VERIFIED" if is_verified else f"BROKEN at {first_broken_entry}"

        table_rows = [["Created At", "Attack Result", "Entry Hash", "Prev Hash", "Status"]]
        for entry in snapshot.ledger_entries:
            table_rows.append(
                [
                    self._format_datetime(entry.created_at),
                    self._short_uuid(entry.attack_result_id),
                    self._truncate_hash(entry.entry_hash),
                    self._truncate_hash(entry.prev_hash or "-"),
                    "VERIFIED" if snapshot.ledger_entry_statuses.get(entry.id, False) else "BROKEN",
                ]
            )

        return [
            Paragraph("Trust Ledger Appendix", styles["section_title"]),
            Spacer(1, 0.12 * inch),
            Paragraph(
                f"Chain of custody status: <b>{escape(status_text)}</b>. Entry hashes are truncated to 16 characters for readability.",
                styles["body"],
            ),
            Spacer(1, 0.12 * inch),
            self._build_small_table(
                table_rows,
                column_widths=[1.55 * inch, 1.35 * inch, 1.7 * inch, 1.7 * inch, 1.0 * inch],
                font_size=8,
            ),
        ]

    def _draw_footer(self, canvas: Any, document: SimpleDocTemplate, attack_run_id: UUID) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
        canvas.line(document.leftMargin, 28, document.pagesize[0] - document.rightMargin, 28)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(document.leftMargin, 16, f"Run ID: {attack_run_id}")
        canvas.drawRightString(document.pagesize[0] - document.rightMargin, 16, "Generated by ShadowLedger")
        canvas.restoreState()

    def _build_styles(self) -> dict[str, ParagraphStyle]:
        base_styles = getSampleStyleSheet()
        return {
            "brand": ParagraphStyle(
                "brand",
                parent=base_styles["Title"],
                fontName="Helvetica-Bold",
                fontSize=28,
                leading=32,
                textColor=colors.HexColor("#0f172a"),
            ),
            "report_title": ParagraphStyle(
                "report_title",
                parent=base_styles["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=26,
                leading=30,
                textColor=colors.HexColor("#0f766e"),
            ),
            "cover_system": ParagraphStyle(
                "cover_system",
                parent=base_styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=18,
                leading=22,
                textColor=colors.HexColor("#1e293b"),
            ),
            "section_title": ParagraphStyle(
                "section_title",
                parent=base_styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=18,
                leading=22,
                textColor=colors.HexColor("#0f172a"),
            ),
            "subsection_title": ParagraphStyle(
                "subsection_title",
                parent=base_styles["Heading3"],
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=15,
                textColor=colors.HexColor("#1e293b"),
            ),
            "finding_title": ParagraphStyle(
                "finding_title",
                parent=base_styles["Heading3"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=14,
                textColor=colors.HexColor("#0f172a"),
                backColor=colors.HexColor("#e2e8f0"),
                borderPadding=6,
            ),
            "body": ParagraphStyle(
                "body",
                parent=base_styles["BodyText"],
                fontName="Helvetica",
                fontSize=10,
                leading=14,
                textColor=colors.HexColor("#334155"),
                splitLongWords=True,
            ),
            "detail": ParagraphStyle(
                "detail",
                parent=base_styles["BodyText"],
                fontName="Helvetica",
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#1e293b"),
                borderColor=colors.HexColor("#cbd5e1"),
                borderWidth=0.5,
                borderPadding=8,
                backColor=colors.HexColor("#f8fafc"),
                splitLongWords=True,
            ),
            "table_cell": ParagraphStyle(
                "table_cell",
                parent=base_styles["BodyText"],
                fontName="Helvetica",
                fontSize=9,
                leading=11,
                textColor=colors.HexColor("#1e293b"),
                splitLongWords=True,
            ),
        }

    def _build_summary_table(
        self,
        rows: list[list[str]],
        styles: dict[str, ParagraphStyle],
    ) -> Table:
        formatted_rows = [
            [
                Paragraph(f"<b>{escape(label)}</b>", styles["table_cell"]),
                Paragraph(escape(value), styles["table_cell"]),
            ]
            for label, value in rows
        ]
        table = Table(formatted_rows, colWidths=[2.1 * inch, 4.6 * inch], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        return table

    def _build_small_table(
        self,
        rows: list[list[str]],
        *,
        column_widths: list[float] | None = None,
        font_size: int = 9,
    ) -> Table:
        table = Table(rows, colWidths=column_widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), font_size),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#ffffff")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return table

    def _format_date_range(self, snapshot: AuditReportSnapshot) -> str:
        timestamps = [result.executed_at for result in snapshot.results if result.executed_at is not None]
        start = snapshot.attack_run.started_at or (min(timestamps) if timestamps else None)
        end = snapshot.attack_run.completed_at or (max(timestamps) if timestamps else None)

        if start is None and end is None:
            return "Not available"
        if start is not None and end is None:
            return f"{self._format_datetime(start)} to In progress"
        if start is None and end is not None:
            return self._format_datetime(end)
        return f"{self._format_datetime(start)} to {self._format_datetime(end)}"

    def _derive_risk_category(self, score: Any) -> str:
        numeric_score = float(score or 0.0)
        if numeric_score <= 19:
            return RiskCategory.SAFE.value
        if numeric_score <= 39:
            return RiskCategory.LOW.value
        if numeric_score <= 59:
            return RiskCategory.MEDIUM.value
        if numeric_score <= 79:
            return RiskCategory.HIGH.value
        return RiskCategory.CRITICAL.value

    def _format_decimal(self, value: Any) -> str:
        if value is None:
            return "Pending"
        return f"{float(value):.2f}"

    def _result_label(self, result: AttackResult) -> str:
        if getattr(result, "attack_vector", None) is not None:
            return f"{result.attack_vector.category.value} / {result.attack_vector.name}"
        return f"Vector {result.attack_vector_id}"

    def _format_datetime(self, value: datetime | None) -> str:
        if value is None:
            return "Pending"
        normalized = value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return normalized.strftime("%Y-%m-%d %H:%M UTC")

    def _escape_multiline(self, value: str) -> str:
        escaped = escape(value or "")
        return escaped.replace("\n", "<br/>")

    def _shorten(self, value: str, max_length: int) -> str:
        if len(value) <= max_length:
            return value
        return f"{value[: max_length - 3]}..."

    def _truncate_hash(self, value: str) -> str:
        if value == "-":
            return value
        return value[:16]

    def _short_uuid(self, value: UUID) -> str:
        return str(value)[:12]
