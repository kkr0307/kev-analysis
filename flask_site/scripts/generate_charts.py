"""(선택) analysis/visualize.py의 CHARTS에 등록된 함수를 모두 실행해서
static/images/charts/<키>.png로 저장합니다.

matplotlib 없이 다른 방법(엑셀, PowerBI, 그림판, 스크린샷 등)으로 PNG를
만들었다면 이 스크립트 없이 static/images/charts/ 폴더에 바로 파일을
넣으면 됩니다. 자세한 사용법은 README.md의 "차트 이미지 교체/추가하기"를
참고하세요.

Usage:
    python scripts/generate_charts.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib.pyplot as plt

from analysis.visualize import CHARTS

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "static", "images", "charts",
)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for key, render in CHARTS.items():
        fig = render()
        path = os.path.join(OUTPUT_DIR, f"{key}.png")
        fig.savefig(path, bbox_inches="tight")
        plt.close(fig)
        print(f"saved {path}")


if __name__ == "__main__":
    main()
