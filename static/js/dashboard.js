// 차트 이미지를 클릭하면 화면 가득 크게 보여줍니다. (발표용)
// 다시 클릭하거나 Esc를 누르면 닫힙니다.

const lightbox = document.getElementById("lightbox");
const lightboxImg = lightbox.querySelector("img");

document.querySelectorAll(".chart-link").forEach((link) => {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    lightboxImg.src = link.href;
    lightboxImg.alt = link.dataset.title;
    lightbox.showModal();
  });
});

lightbox.addEventListener("click", () => lightbox.close());
