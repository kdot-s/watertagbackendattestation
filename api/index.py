import hashlib
import json
import os
import time
from base64 import b64decode, urlsafe_b64decode
from urllib.parse import quote
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

oculusappid = "1788453785395230"
oculussecret = "d55698f2a8b6d087ae811a371db49e28"
photonappid = "9a31e92b-1d5b-43b9-abfc-a905417ba9bd"
playfabtitle = "1F4F43"
playfabsecret = "G7UYNFAHD95YBOTM33ARSFB6U1PBDZZ3D4GRNG9WNQ6SUJAYHS"
apiver = "v1"
devkey = "skibidididitoilet"
usednonces = set()
pending = {}

def pfurl(path):
    return f"https://{playfabtitle}.playfabapi.com{path}"

def pfheaders():
    return {"Content-Type": "application/json", "X-SecretKey": playfabsecret}

def logindev():
    thingy = f"DEV_{os.urandom(8).hex()}"
    r = requests.post(pfurl("/Server/LoginWithServerCustomId"), headers=pfheaders(), json={"ServerCustomId": thingy, "CreateAccount": True})
    data = r.json()
    if data.get("code") != 200:
        return None
    return {"playfabid": data["data"]["PlayFabId"], "sessionticket": data["data"]["SessionTicket"]}

def getphotontoken(playfabid):
    r = requests.post(pfurl("/Server/GetPhotonAuthenticationToken"), headers=pfheaders(), json={"PlayFabId": playfabid, "PhotonApplicationId": photonappid})
    data = r.json()
    if data.get("code") != 200:
        return None
    return data["data"]["PhotonCustomAuthenticationToken"]

def makeattest(playfabid, orgscope):
    raw = f"{playfabid}:{orgscope}:{int(time.time() * 1000)}:{os.urandom(16).hex()}"
    return hashlib.sha256(f"{apiver}_{raw}".encode()).hexdigest()

def issteamticket(thingy):
    return len(thingy) > 64 and all(c in "0123456789abcdefABCDEF" for c in thingy)

def photonresponse(playfabid):
    token = getphotontoken(playfabid)
    if not token:
        return None
    return {"ResultCode": 1, "UserId": playfabid, "PhotonToken": token}

def cleanpending():
    now = time.time()
    expired = [k for k, v in pending.items() if now - v["ts"] > 5 * 60]
    for k in expired:
        del pending[k]

@app.route("/playfab/loginwithoculus", methods=["POST"])
def loginwithoculus():
    try:
        if request.headers.get("devauth") == devkey:
            dev = logindev()
            if not dev:
                return jsonify({"error": "PlayFab login failed"}), 500
            thingy = hashlib.sha256(f"{apiver}_dev_{dev['playfabid']}_{int(time.time() * 1000)}".encode()).hexdigest()
            pending[thingy] = {"playfabid": dev["playfabid"], "orgscope": "dev", "ts": time.time()}
            return jsonify({"PlayfabID": dev["playfabid"], "SessionTicket": dev["sessionticket"], "attestpreauth": thingy})

        body = request.get_json()
        uid = body.get("id")
        varsthingy = body.get("vars", {})
        nonce = varsthingy.get("nonce")
        orgscope = varsthingy.get("orgscope")
        integrity = body.get("integrity", {})

        authheader = request.headers.get("Authorization", "")
        if not authheader.startswith("Basic "):
            return jsonify({"error": "Missing authorization"}), 401
        decoded = b64decode(authheader[6:]).decode("utf-8")
        parts = decoded.split(":")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return jsonify({"error": "Bad authorization format"}), 401

        if nonce in usednonces:
            return jsonify({"error": "Nonce already used"}), 401
        usednonces.add(nonce)

        noncecheck = requests.post("https://graph.oculus.com/user_nonce_validate", headers={"Content-Type": "application/x-www-form-urlencoded"}, data={"access_token": f"OC|{oculusappid}|{oculussecret}", "nonce": nonce, "user_id": uid})
        if not noncecheck.json().get("is_valid"):
            return jsonify({"error": "Meta nonce validation failed"}), 401

        orgcheck = requests.get(f"https://graph.oculus.com/{uid}?fields=org_scoped_id&access_token=OC|{oculusappid}|{oculussecret}")
        if orgcheck.json().get("org_scoped_id") != orgscope:
            return jsonify({"error": "Org scoped ID mismatch"}), 401

        if not integrity.get("package") or not integrity.get("version") or not integrity.get("attestation"):
            return jsonify({"error": "Missing app integrity"}), 401
        if not (integrity["package"][0] or "").startswith("com."):
            return jsonify({"error": "Invalid package"}), 401

        attestcheck = requests.post(f"https://graph.oculus.com/integrity_report", data={"access_token": f"OC|{oculusappid}|{oculussecret}", "integrity_token": integrity["attestation"]})
        attestdata = attestcheck.json()
        if not attestdata.get("data") or attestdata["data"][0].get("message") != "success":
            return jsonify({"error": "Attestation verification failed"}), 401

        rawclaims = attestdata["data"][0].get("claims", "")
        padding = (4 - len(rawclaims) % 4) % 4
        claims = json.loads(urlsafe_b64decode(rawclaims + "=" * padding).decode("utf-8"))

        if claims.get("device_ban", {}).get("is_banned"):
            return jsonify({"error": "YOU HAVE BEEN BANNED, NO UNBAN DETAILS YET."}), 403
        if claims["app_state"]["app_integrity_state"] != "StoreRecognized":
            return jsonify({"error": "UNABLE TO AUTHENTICATE WITH MOTHERSHIP, YOU ARE USING A MODDED VERSION OF THIS GAME."}), 401
        if claims["device_state"]["device_integrity_state"] == "NotTrusted":
            return jsonify({"error": "UNABLE TO AUTHENTICATE WITH MOTHERSHIP, YOU ARE USING A MODDED VERSION OF THIS GAME."}), 401
        if claims["app_state"]["package_id"] != integrity["package"][0]:
            return jsonify({"error": "Package mismatch"}), 401
        if time.time() > claims["request_details"]["exp"]:
            return jsonify({"error": "Attestation token expired"}), 401

        # attestation passed - use orgscope as the stable user id, no playfab login needed
        playfabid = hashlib.sha256(f"oculus_{orgscope}".encode()).hexdigest()[:28].upper()
        thingy2 = makeattest(playfabid, orgscope)
        cleanpending()
        pending[thingy2] = {"playfabid": playfabid, "orgscope": orgscope, "ts": time.time()}
        return jsonify({"PlayfabID": playfabid, "SessionTicket": "", "attestpreauth": thingy2})

    except Exception as e:
        print(e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/attestation/photon", methods=["POST"])
def attestationphoton():
    try:
        if request.args.get("DevAuth") == devkey:
            username = request.args.get("username")
            if not username:
                return jsonify({"error": "Missing username"}), 401
            dev = logindev()
            if not dev:
                return jsonify({"error": "PlayFab login failed"}), 500
            thingy3 = photonresponse(dev["playfabid"])
            if not thingy3:
                return jsonify({"error": "Photon token fetch failed"}), 500
            return jsonify(thingy3)

        username = request.args.get("username")
        attestation = request.args.get("attestation")
        if not username or not attestation:
            return jsonify({"error": "Missing params"}), 401

        if issteamticket(attestation):
            # steam path still needs playfab
            r = requests.post(pfurl("/Server/LoginWithSteam"), headers=pfheaders(), json={"SteamTicket": attestation, "CreateAccount": True})
            data = r.json()
            if data.get("code") != 200:
                return jsonify({"error": "Steam login failed"}), 401
            pf = {"playfabid": data["data"]["PlayFabId"]}
            if pf["playfabid"] != username:
                return jsonify({"error": "Username mismatch"}), 401
            thingy4 = photonresponse(pf["playfabid"])
            if not thingy4:
                return jsonify({"error": "Photon token fetch failed"}), 500
            return jsonify(thingy4)

        thingy5 = pending.get(attestation)
        if not thingy5:
            return jsonify({"error": "Unknown or expired token"}), 401
        if thingy5["playfabid"] != username:
            return jsonify({"error": "Username mismatch"}), 401
        if time.time() - thingy5["ts"] > 5 * 60:
            del pending[attestation]
            return jsonify({"error": "Token expired"}), 401

        thingy6 = photonresponse(thingy5["playfabid"])
        if not thingy6:
            return jsonify({"error": "Photon token fetch failed"}), 500
        del pending[attestation]
        return jsonify(thingy6)

    except Exception as e:
        print(e)
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(port=3000)
