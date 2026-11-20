import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import router from "@/router/router.js";
const getHeaders = () => {
	let headers = {
		"Content-Type": "application/json"
	}
	try{
		const store = DashboardConfigurationStore();
		const crossServer = store.getActiveCrossServer();
		if (crossServer){
			headers['wg-dashboard-apikey'] = crossServer.apiKey
			if (crossServer.headers){
				for (let header of Object.values(crossServer.headers)){
					if (header.key && header.value && !Object.keys(headers).includes(header.key)){
						headers[header.key] = header.value
					}
				}
			}
		}
	}catch (e) {
		
	}


	return headers
}

export const getUrl = (url) => {
	try{
		const store = DashboardConfigurationStore();
		const apiKey = store.getActiveCrossServer();
		if (apiKey){
			return `${apiKey.host}${url}`
		}
	}catch (e){}
	if (import.meta.env.MODE === 'development') {
		return url;
	}
	// const appPrefix = window.APP_PREFIX || '';
	return `./.${url}`;
}

const NETWORK_ERROR = "Cannot reach WGDashboard server, please try again"
const ERROR_TOAST_INTERVAL = 10000
let lastErrorToast = {content: "", time: 0}
let redirectingToSignIn = false

// Show an error toast, but do not flood the UI while the server is down and polling keeps failing
const notifyError = (content) => {
	const now = Date.now()
	if (lastErrorToast.content === content && now - lastErrorToast.time < ERROR_TOAST_INTERVAL) return
	lastErrorToast = {content, time: now}
	try{
		DashboardConfigurationStore().newMessage("WGDashboard", content, "danger")
	}catch (e){}
}

// Only a real 401 from the server ends the session; remember where we were to come back after sign in
const sessionEnded = () => {
	const current = router.currentRoute.value
	if (redirectingToSignIn || current.path === '/signin') return
	redirectingToSignIn = true
	try{
		const store = DashboardConfigurationStore()
		if (current.meta?.requiresAuth) store.Redirect = current
		store.newMessage("WGDashboard", "Sign in session ended, please sign in again", "warning")
	}catch (e){}
	router.push({path: '/signin'}).finally(() => { redirectingToSignIn = false })
}

const runCallback = async (callback, data) => {
	if (!callback) return
	try{
		await callback(data)
	}catch (e){
		console.error("Error in request callback:", e)
	}
}

/*
 * Returns the parsed response body. On a transport/HTTP error it returns
 * {status: false, message, data: null, networkError: true} instead of
 * kicking the user out to the sign in page.
 *  - GET: callback is skipped on error (polling keeps the last good data), a toast is shown
 *  - POST/PUT/DELETE: callback receives the error object, so the caller can reset its
 *    spinners and show the message; if there is no callback, a toast is shown
 */
const request = async (method, url, {params, body} = {}, callback = undefined) => {
	let fullUrl = getUrl(url)
	if (method === "GET") fullUrl += `?${new URLSearchParams(params).toString()}`
	const init = {headers: getHeaders(), method}
	if (method !== "GET") init.body = JSON.stringify(body)

	let message
	let unauthorized = false
	try{
		const res = await fetch(fullUrl, init)
		if (res.status === 401){
			unauthorized = true
			message = "Sign in session ended, please sign in again"
		}else if (!res.ok){
			message = `Server error: ${res.status} ${res.statusText}`.trim()
		}else{
			let data
			try{
				data = await res.json()
			}catch (e){
				message = "Invalid response from server"
			}
			if (message === undefined){
				await runCallback(callback, data)
				return data
			}
		}
	}catch (e){
		console.log("Error:", e)
		message = NETWORK_ERROR
	}

	const result = {status: false, message, data: null, networkError: true}
	if (unauthorized){
		sessionEnded()
		return result
	}
	if (method !== "GET" && callback){
		await runCallback(callback, result)
	}else{
		notifyError(message)
	}
	return result
}

export const fetchGet = async (url, params=undefined, callback=undefined) =>
	request("GET", url, {params}, callback)

export const fetchPost = async (url, body, callback) =>
	request("POST", url, {body}, callback)

export const fetchPut = async (url, body, callback) =>
	request("PUT", url, {body}, callback)

export const fetchDelete = async (url, body, callback) =>
	request("DELETE", url, {body}, callback)
