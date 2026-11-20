/*
 * Save content as a file in the browser.
 *
 * Mobile Safari opens blobs with a type it can display (text/plain, the
 * non-standard text/conf, ...) by navigating the current tab to the blob URL
 * instead of downloading them, which also aborts the dashboard's pending
 * requests. application/octet-stream is always downloaded. The anchor has to
 * be attached to the document for the click to work in every browser, and the
 * object URL is revoked once the download had time to start.
 */
export const downloadFile = (content, filename, type = "application/octet-stream") => {
	const blob = content instanceof Blob ? content : new Blob([content], { type })
	const url = URL.createObjectURL(blob)
	const a = document.createElement("a")
	a.href = url
	a.download = filename
	a.rel = "noopener"
	a.style.display = "none"
	document.body.appendChild(a)
	a.click()
	document.body.removeChild(a)
	setTimeout(() => URL.revokeObjectURL(url), 60000)
}
