import * as network from "./network.js";

const columns = ["ID", "Name", "Category", "Price"];
let tableBody;
let errorElem;

HTMLElement.prototype.make = function (...types) {
    return types.reduce((lastElem, elemType) =>
        lastElem.appendChild(document.createElement(elemType)), this);
}

function showError(err) {
    errorElem.innerText = `Error: ${err}`;
    errorElem.classList.add("m-2", "p-2");
}

function clearError(err) {
    errorElem.innerText = "";
    errorElem.classList.remove("m-2", "p-2");
}

function createStructure() {
    const targetElement = document.getElementById("target");
    targetElement.innerHTML = "";
    errorElem = targetElement.make("div");
    errorElem.classList.add("h6", "bg-danger", "text-center", "text-white");
    return targetElement;
}

function createContent() {
    const targetElement = createStructure();
    const table = targetElement.make("table");
    table.classList.add("table", "table-sm", "table-striped", "table-bordered");
    const headerRow = table.make("thead", "tr");
    columns.concat([""]).forEach(col => {
        const th = headerRow.make("th");
        th.innerText = col;
    });
    tableBody = table.make("tbody");
    const footerRow = table.make("tfoot", "tr");
    footerRow.make("td");
    columns.filter(col => col != "ID").forEach(col => {
        const input = footerRow.make("td", "input");
        input.name = input.id = col;
        input.placeholder = `Enter ${col.toLowerCase()}`;
    });
    const button = footerRow.make("td", "button");
    button.classList = "btn btn-sm btn-success";
    button.innerText = "Add";
    button.addEventListener("click", async () => {
        const product = {};
        columns.forEach(col => product[col] = document.getElementById(col)?.value);
        await network.createProduct(product, populateTable, showError);
    });
}

function createTableContents(products) {
    tableBody.innerHTML = "";
    products.forEach(p => {
        const row = tableBody.appendChild(document.createElement("tr"));
        columns.forEach(col => {
            const cell = row.appendChild(document.createElement("td"));
            cell.innerText = p[col.toLowerCase()];
        });
        const button = row.appendChild(document.createElement("td")
            .appendChild(document.createElement("button")));
        button.classList.add("btn", "btn-sm", "btn-danger");
        button.textContent = "Delete";
        button.addEventListener("click", async () =>
            await network.deleteProduct(p.id, populateTable, showError));
    });
}

async function populateTable(products) {
    clearError();
    await network.loadData(createTableContents, showError);
}

document.addEventListener("DOMContentLoaded", () => {
    createContent();
    populateTable();
})
