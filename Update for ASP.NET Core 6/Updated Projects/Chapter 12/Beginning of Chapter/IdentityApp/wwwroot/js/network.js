const baseUrl = "https://localhost:44350/api/data";

export const loadData = async function (callback, errorHandler) {
    const response = await fetch(baseUrl, {
        redirect: "manual"
    });
    processResponse(response, async () => callback(await response.json()),
        errorHandler);
}

export const createProduct = async function (product, callback, errorHandler) {
    const response = await fetch(baseUrl, {
        method: "POST",
        body: JSON.stringify(product),
        headers: {
            "Content-Type": "application/json"
        }
    });
    processResponse(response, callback, errorHandler);
}

export const deleteProduct = async function (id, callback, errorHandler) {
    const response = await fetch(`${baseUrl}/${id}`, {
        method: "DELETE"
    });
    processResponse(response, callback, errorHandler);
}

function processResponse(response, callback, errorHandler) {
    if (response.ok) {
        callback();
    } else {
        errorHandler(response.status);
    }
}
