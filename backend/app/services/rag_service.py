"""Lightweight Security Knowledge Retrieval Service (RAG) using local markdown files."""

from dataclasses import dataclass
import logging
from pathlib import Path
import re
from typing import Dict, List, Optional

from backend.app.config import settings
from backend.app.models.schemas import KnowledgeEvidence, ThreatType

logger = logging.getLogger("scamshield.rag")


@dataclass
class KnowledgeDocumentChunk:
    """Document snippet representation from knowledge files."""
    source_file: str
    section_title: str
    content: str
    keywords: List[str]


class SecurityKnowledgeRAG:
    """Local Markdown knowledge base retriever with keyword and BM25 scoring."""

    def __init__(self, knowledge_dir: Optional[Path] = None):
        self.knowledge_dir = knowledge_dir or settings.KNOWLEDGE_DIR
        self.chunks: List[KnowledgeDocumentChunk] = []
        self._bm25 = None
        self._tokenized_corpus: List[List[str]] = []
        self._load_knowledge_base()

    def _tokenize(self, text: str) -> List[str]:
        """Simple clean word tokenizer."""
        return [word.lower() for word in re.findall(r"\b\w{3,}\b", text)]

    def _load_knowledge_base(self) -> None:
        """Scan directory and index markdown documents into searchable chunks."""
        if not self.knowledge_dir.exists():
            logger.warning("Knowledge directory does not exist: %s", self.knowledge_dir)
            return

        md_files = list(self.knowledge_dir.glob("*.md"))
        logger.info("Found %d knowledge base files in %s", len(md_files), self.knowledge_dir)

        for file_path in md_files:
            try:
                content = file_path.read_text(encoding="utf-8")
                sections = re.split(r"\n(?=##\s+)", content)
                for sec in sections:
                    sec_clean = sec.strip()
                    if not sec_clean:
                        continue
                    lines = sec_clean.split("\n")
                    first_line = lines[0].replace("#", "").strip() if lines else file_path.name
                    body = "\n".join(lines[1:]).strip() if len(lines) > 1 else sec_clean
                    
                    tokens = self._tokenize(sec_clean)
                    chunk = KnowledgeDocumentChunk(
                        source_file=file_path.name,
                        section_title=first_line,
                        content=sec_clean,
                        keywords=list(set(tokens)),
                    )
                    self.chunks.append(chunk)
            except Exception as e:
                logger.error("Failed to load knowledge file %s: %s", file_path.name, str(e))

        if self.chunks:
            self._tokenized_corpus = [self._tokenize(c.content) for c in self.chunks]
            try:
                from rank_bm25 import BM25Okapi
                self._bm25 = BM25Okapi(self._tokenized_corpus)
                logger.info("BM25 index initialized with %d chunks", len(self.chunks))
            except ImportError:
                logger.info("rank-bm25 not available, falling back to jaccard keyword scoring.")
                self._bm25 = None

    def retrieve(
        self,
        query: str,
        threat_types: Optional[List[ThreatType]] = None,
        top_k: int = 3,
    ) -> List[KnowledgeEvidence]:
        """Retrieve most relevant knowledge snippets based on content and detected threats."""
        if not self.chunks:
            return []

        # Map threat types to relevant file names or concept keywords
        threat_type_keywords = []
        if threat_types:
            for tt in threat_types:
                threat_type_keywords.extend(tt.value.lower().replace("_", " ").split())

        query_tokens = self._tokenize(query) + threat_type_keywords
        if not query_tokens:
            return []

        scores: List[float] = []

        if self._bm25 is not None:
            raw_scores = self._bm25.get_scores(query_tokens)
            max_s = max(raw_scores) if max(raw_scores) > 0 else 1.0
            scores = [min(1.0, max(0.0, s / (max_s * 1.2))) for s in raw_scores]
        else:
            # Jaccard keyword overlap
            query_set = set(query_tokens)
            for chunk in self.chunks:
                chunk_set = set(chunk.keywords)
                intersection = query_set.intersection(chunk_set)
                union = query_set.union(chunk_set)
                score = len(intersection) / len(union) if union else 0.0
                scores.append(min(1.0, score * 3.0))

        # Rank and filter top_k with non-zero relevance
        ranked_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        results: List[KnowledgeEvidence] = []

        for idx in ranked_indices:
            score = float(scores[idx])
            if score < 0.05:
                continue
            chunk = self.chunks[idx]
            # Truncate evidence snippet cleanly to ~300 chars
            snippet = chunk.content.replace("\n", " ").strip()
            if len(snippet) > 350:
                snippet = snippet[:347] + "..."

            results.append(
                KnowledgeEvidence(
                    source=chunk.source_file,
                    relevance=round(score, 2),
                    evidence=snippet,
                )
            )
            if len(results) >= top_k:
                break

        return results


# Global singleton instance
rag_service = SecurityKnowledgeRAG()
