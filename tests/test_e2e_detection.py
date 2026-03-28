"""
End-to-end detection workflow test.

This test validates the complete detection workflow by:
1. Loading test skill fixtures (white/clean and black/malicious)
2. Running the StaticAnalyzer on each skill
3. Verifying white skills produce no high-severity findings
4. Verifying black skills produce expected vulnerability patterns
5. Generating a summary report
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.static_analyzer import StaticAnalyzer
from src.models.common import RiskLevel, VulnerabilityPattern, VulnerabilityCategory


# Test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "skills"


class E2ETestRunner:
    """End-to-end test runner for detection workflow."""

    def __init__(self):
        self.analyzer = StaticAnalyzer()
        self.results = {"white_skills": [], "black_skills": [], "summary": {}}

    def load_skill_directory(self, skill_dir: Path) -> Tuple[str, List[Dict]]:
        """
        Load a skill directory into the format expected by the analyzer.

        Args:
            skill_dir: Path to skill directory containing SKILL.md and scripts

        Returns:
            Tuple of (skill_md_content, scripts_list)
        """
        skill_md_path = skill_dir / "SKILL.md"

        if not skill_md_path.exists():
            raise FileNotFoundError(f"SKILL.md not found in {skill_dir}")

        # Read SKILL.md
        skill_md = skill_md_path.read_text(encoding="utf-8")

        # Read all script files
        scripts = []
        for file_path in skill_dir.iterdir():
            if file_path.is_file() and file_path.name != "SKILL.md":
                content = file_path.read_text(encoding="utf-8")
                scripts.append(
                    {
                        "filename": file_path.name,
                        "content": content,
                        "language": self._detect_language(file_path.suffix),
                    }
                )

        return skill_md, scripts

    def _detect_language(self, suffix: str) -> str:
        """Detect language from file extension."""
        language_map = {
            ".py": "python",
            ".sh": "shell",
            ".bash": "shell",
            ".js": "javascript",
            ".ts": "typescript",
            ".json": "json",
            ".yaml": "yaml",
            ".yml": "yaml",
        }
        return language_map.get(suffix, "text")

    async def analyze_skill(self, skill_dir: Path, skill_type: str) -> Dict:
        """
        Analyze a single skill and return results.

        Args:
            skill_dir: Path to skill directory
            skill_type: "white" or "black"

        Returns:
            Analysis results dictionary
        """
        skill_name = skill_dir.name
        print(f"\n{'='*60}")
        print(f"Analyzing {skill_type} skill: {skill_name}")
        print(f"{'='*60}")

        try:
            skill_md, scripts = self.load_skill_directory(skill_dir)

            # Determine skill language from content (not script language)
            # All our test skills use English content
            skill_language = "en"

            result = await self.analyzer.analyze(
                skill_md=skill_md,
                scripts=scripts,
                skill_id=f"{skill_type}-{skill_name}",
                language=skill_language,
            )

            # Extract key information
            scan_result = {
                "name": skill_name,
                "type": skill_type,
                "risk_level": result.get("risk_level", "unknown"),
                "risk_score": result.get("risk_score", 0),
                "vulnerabilities": [],
                "passed": True,
            }

            # Collect vulnerabilities
            vulns = result.get("vulnerabilities", [])
            for vuln in vulns:
                scan_result["vulnerabilities"].append(
                    {
                        "pattern": vuln.get("pattern", "unknown"),
                        "category": vuln.get("category", "unknown"),
                        "severity": vuln.get("severity", "unknown"),
                        "confidence": vuln.get("confidence", 0),
                        "description_en": vuln.get("description_en", ""),
                    }
                )

            # Print results
            self._print_analysis_result(scan_result)

            return scan_result

        except Exception as e:
            print(f"Error analyzing {skill_name}: {e}")
            return {"name": skill_name, "type": skill_type, "error": str(e), "passed": False}

    def _print_analysis_result(self, result: Dict) -> None:
        """Print analysis results in a readable format."""
        print(f"Risk Level: {result['risk_level'].upper()}")
        print(f"Risk Score: {result['risk_score']:.2f}")

        vulns = result.get("vulnerabilities", [])
        if vulns:
            print(f"\nVulnerabilities Found ({len(vulns)}):")
            for v in vulns:
                print(f"  - [{v['pattern']}] {v['category']} ({v['severity']})")
                if v.get("description_en"):
                    print(f"    {v['description_en'][:80]}...")
        else:
            print("\nNo vulnerabilities found.")

    def validate_white_skill(self, result: Dict) -> bool:
        """
        Validate that a white (clean) skill passes detection.

        White skills should have:
        - Risk level: safe or warning (not dangerous/malicious)
        - No high-severity vulnerabilities
        """
        if result.get("error"):
            print(f"  ❌ FAIL: Error during analysis")
            return False

        risk_level = result.get("risk_level", "")
        if risk_level in ["dangerous", "malicious"]:
            print(f"  ❌ FAIL: White skill marked as {risk_level}")
            return False

        # Check for high-severity vulnerabilities
        high_sev_vulns = [
            v for v in result.get("vulnerabilities", []) if v.get("severity") == "high"
        ]
        if high_sev_vulns:
            print(f"  ❌ FAIL: Found {len(high_sev_vulns)} high-severity vulnerabilities")
            return False

        print(f"  ✅ PASS: White skill correctly identified as clean")
        return True

    def validate_black_skill(self, result: Dict, expected_patterns: List[str] = None) -> bool:
        """
        Validate that a black (malicious) skill is detected.

        Black skills should have:
        - Risk level: warning, dangerous, or malicious (anything not "safe")
        - At least one vulnerability detected
        - Optionally: specific expected patterns
        """
        if result.get("error"):
            print(f"  ❌ FAIL: Error during analysis")
            return False

        risk_level = result.get("risk_level", "")
        if risk_level == "safe":
            print(f"  ❌ FAIL: Black skill not detected (risk_level: {risk_level})")
            return False

        vulns = result.get("vulnerabilities", [])
        if not vulns:
            print(f"  ❌ FAIL: No vulnerabilities detected in malicious skill")
            return False

        # Check for expected patterns if provided
        if expected_patterns:
            detected_patterns = [v.get("pattern") for v in vulns]
            missing = [p for p in expected_patterns if p not in detected_patterns]
            if missing:
                print(f"  ⚠️  WARNING: Expected patterns not found: {missing}")

        print(f"  ✅ PASS: Black skill detected ({len(vulns)} vulnerabilities)")
        return True

    async def run_all_tests(self) -> Dict:
        """Run tests on all skill fixtures."""
        print("\n" + "=" * 80)
        print("SKILLSCAN END-TO-END DETECTION WORKFLOW TEST")
        print("=" * 80)

        # Test white skills
        white_dir = FIXTURES_DIR / "white"
        if white_dir.exists():
            print("\n📋 Testing WHITE (clean) skills...")
            print("-" * 60)

            for skill_dir in white_dir.iterdir():
                if skill_dir.is_dir():
                    result = await self.analyze_skill(skill_dir, "white")
                    result["validation_passed"] = self.validate_white_skill(result)
                    self.results["white_skills"].append(result)

        # Test black skills
        black_dir = FIXTURES_DIR / "black"
        if black_dir.exists():
            print("\n📋 Testing BLACK (malicious) skills...")
            print("-" * 60)

            # Expected patterns for each skill type
            expected_patterns = {
                "prompt-injection-skill": ["P1", "P2", "P4"],
                "data-exfiltration-skill": ["E1", "E2", "E3"],
                "privilege-escalation-skill": ["PE1", "PE2", "PE3"],
                "supply-chain-skill": ["SC1", "SC2", "SC3"],
                "comprehensive-malicious-skill": None,  # Any pattern is fine
            }

            for skill_dir in black_dir.iterdir():
                if skill_dir.is_dir():
                    result = await self.analyze_skill(skill_dir, "black")
                    patterns = expected_patterns.get(skill_dir.name)
                    result["validation_passed"] = self.validate_black_skill(result, patterns)
                    self.results["black_skills"].append(result)

        # Generate summary
        self._generate_summary()

        return self.results

    def _generate_summary(self) -> None:
        """Generate and print test summary."""
        print("\n" + "=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)

        white_results = self.results["white_skills"]
        black_results = self.results["black_skills"]

        white_passed = sum(1 for r in white_results if r.get("validation_passed"))
        black_passed = sum(1 for r in black_results if r.get("validation_passed"))

        print(f"\nWhite Skills: {white_passed}/{len(white_results)} passed")
        for r in white_results:
            status = "✅" if r.get("validation_passed") else "❌"
            print(f"  {status} {r['name']}: {r.get('risk_level', 'unknown')}")

        print(f"\nBlack Skills: {black_passed}/{len(black_results)} passed")
        for r in black_results:
            status = "✅" if r.get("validation_passed") else "❌"
            vuln_count = len(r.get("vulnerabilities", []))
            print(f"  {status} {r['name']}: {r.get('risk_level', 'unknown')} ({vuln_count} vulns)")

        total = len(white_results) + len(black_results)
        passed = white_passed + black_passed

        print(f"\n{'='*40}")
        print(f"OVERALL: {passed}/{total} tests passed")

        if passed == total:
            print("🎉 All tests passed!")
        else:
            print(f"⚠️  {total - passed} test(s) failed")

        # Save results to file
        results_file = Path(__file__).parent / "test_results.json"
        with open(results_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed results saved to: {results_file}")


async def main():
    """Main entry point."""
    runner = E2ETestRunner()
    results = await runner.run_all_tests()

    # Return exit code based on results
    white_passed = sum(1 for r in results["white_skills"] if r.get("validation_passed"))
    black_passed = sum(1 for r in results["black_skills"] if r.get("validation_passed"))
    total = len(results["white_skills"]) + len(results["black_skills"])
    passed = white_passed + black_passed

    return 0 if passed == total else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
