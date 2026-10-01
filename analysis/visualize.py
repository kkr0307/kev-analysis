"""(선택) matplotlib으로 대시보드용 PNG를 만들 때 쓰는 함수들입니다.

대시보드는 static/images/charts/i1.png ~ i6.png 파일만 봅니다. 자세한 사용법은
README.md의 "나만의 시각화 추가하기"를 참고하세요.

파이썬으로 그리고 싶다면: 함수를 추가해 matplotlib figure를 반환하게 하고,
아래 CHARTS 딕셔너리에 `"i2": 함수`처럼 등록한 뒤
`python scripts/generate_charts.py`를 실행하세요.
"""
import matplotlib

matplotlib.use("Agg")  # 화면(디스플레이) 없는 서버에서도 그래프를 그리기 위한 설정
import matplotlib.pyplot as plt
from matplotlib import font_manager

from analysis.kev_analysis import get_trends

# 한글이 깨지지 않도록(네모 박스로 나오지 않도록) 시스템에 설치된 한글 폰트를
# 자동으로 찾아 씁니다. Windows/Mac은 보통 기본 폰트가 이미 한글을 지원해서
# 여기서 바로 찾힙니다. 한글 폰트가 하나도 없는 리눅스라면 아래처럼
# 설치해 주세요: sudo apt-get install fonts-nanum
_KOREAN_FONT_CANDIDATES = [
    "Malgun Gothic",       # Windows 기본
    "AppleGothic",         # macOS 기본
    "Apple SD Gothic Neo", # macOS(최신)
    "NanumGothic",         # Linux (fonts-nanum)
    "Noto Sans CJK KR",
    "Noto Sans KR",
]


def _use_korean_font():
    available = {f.name for f in font_manager.fontManager.ttflist}
    for name in _KOREAN_FONT_CANDIDATES:
        if name in available:
            plt.rcParams["font.family"] = name
            break
    else:
        print(
            "[visualize] 한글 폰트를 찾지 못했습니다. 그래프의 한글이 네모 박스로 "
            "보일 수 있습니다. (리눅스라면: sudo apt-get install fonts-nanum)"
        )
    plt.rcParams["axes.unicode_minus"] = False  # 한글 폰트 사용 시 '-' 기호 깨짐 방지


_use_korean_font()


def example_monthly_trend():
    """예시: 월별 KEV 등록 추이를 선 그래프로 그려 matplotlib figure를 반환합니다.

    이 함수를 그대로 복사한 뒤 get_trends() 대신 get_vendor_stats(),
    get_cwe_stats(), get_ransomware_stats() 등을 넣으면 다른 차트도
    같은 방식으로 만들 수 있습니다. (모든 통계 함수는 analysis/kev_analysis.py
    에 있습니다.)
    """
    data = get_trends()  # [{"month": "2021-11", "count": 291}, ...]
    months = [row["month"] for row in data]
    counts = [row["count"] for row in data]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(months, counts, marker="o", markersize=3, linewidth=1.5)
    ax.set_title("월별 KEV 등록 추이")
    ax.set_xlabel("등록 월")
    ax.set_ylabel("건수")
    ax.tick_params(axis="x", rotation=90, labelsize=7)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()

    return fig


# ---------------------------------------------------------------------------
# 여기부터는 여러분의 차트를 추가하는 자리입니다. 아래는 시작할 때 참고할 수
# 있는 틀(템플릿)입니다. 주석을 해제하고 내용을 채우면 바로 동작합니다.
# ---------------------------------------------------------------------------
#
# from analysis.kev_analysis import get_vendor_stats
#
# def example_top_vendors():
#     data = get_vendor_stats(limit=10)  # [{"vendor": "Microsoft", "count": 389}, ...]
#     vendors = [row["vendor"] for row in data]
#     counts = [row["count"] for row in data]
#
#     fig, ax = plt.subplots(figsize=(8, 5))
#     ax.barh(vendors, counts)
#     ax.invert_yaxis()  # 가장 많은 벤더가 위로 오도록
#     ax.set_title("벤더별 KEV 건수 Top 10")
#     fig.tight_layout()
#
#     return fig
#
# CHARTS["i2"] = example_top_vendors


# scripts/generate_charts.py가 읽는 목록입니다. 키는 i1 ~ i6 중에서 씁니다.
CHARTS = {
    "i1": example_monthly_trend,
}
