function setupImagePreview() {
  const input = document.querySelector("[data-image-preview]");
  const target = document.querySelector("[data-image-preview-target]");
  if (!input || !target) return;

  input.addEventListener("change", () => {
    const file = input.files && input.files[0];
    if (!file) {
      target.classList.add("d-none");
      target.removeAttribute("src");
      return;
    }

    target.src = URL.createObjectURL(file);
    target.classList.remove("d-none");
  });
}

function setupConfirmForms() {
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const message = form.dataset.confirm || "계속 진행하시겠습니까?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  setupImagePreview();
  setupConfirmForms();
});
