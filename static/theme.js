(function () {
  const key = "themeMode";
  const body = document.body;
  const btn = document.querySelector("[data-theme-toggle]");

  const apply = (mode) => {
    const dark = mode === "dark";
    body.classList.toggle("dark", dark);
    if (btn) {
      btn.textContent = dark ? "Light" : "Dark";
    }
  };

  apply(localStorage.getItem(key) || "light");

  if (btn) {
    btn.addEventListener("click", function () {
      const next = body.classList.contains("dark") ? "light" : "dark";
      localStorage.setItem(key, next);
      apply(next);
    });
  }
})();
