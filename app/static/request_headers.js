(() => {
  const rows = document.querySelector("#custom-header-rows");
  const template = document.querySelector("#custom-header-row-template");
  const addButton = document.querySelector("#add-custom-header");
  const maximumRows = 20;

  if (!rows || !template || !addButton) return;

  const updateControls = () => {
    const currentRows = rows.querySelectorAll(".header-row");
    addButton.disabled = currentRows.length >= maximumRows;
    currentRows.forEach((row) => {
      const removeButton = row.querySelector(".remove-header");
      if (removeButton) removeButton.disabled = currentRows.length === 1;
    });
  };

  addButton.addEventListener("click", () => {
    if (rows.querySelectorAll(".header-row").length >= maximumRows) return;
    rows.append(template.content.cloneNode(true));
    updateControls();
    const names = rows.querySelectorAll('input[name="custom_header_name"]');
    names[names.length - 1].focus();
  });

  rows.addEventListener("click", (event) => {
    const removeButton = event.target.closest(".remove-header");
    if (!removeButton) return;
    const currentRows = rows.querySelectorAll(".header-row");
    if (currentRows.length > 1) removeButton.closest(".header-row").remove();
    updateControls();
  });

  updateControls();
})();
