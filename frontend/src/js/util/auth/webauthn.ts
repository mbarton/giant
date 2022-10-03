// See WebAuthnPublicKeyRegistration in the backend
type WebAuthnPublicKeyRegistration = {
    id: string,
    clientDataJson: string,
    attestationObject: string
};

export async function registerSecurityKey(challenge: string, name: string, userHandle: string, username: string, displayName: string): Promise<WebAuthnPublicKeyRegistration> {
    const resp = await navigator.credentials.create({
        publicKey: {
            challenge: Uint8Array.from(atob(challenge), c => c.charCodeAt(0)),
            rp: {
                name,
                // TODO MRB: get this from client config?
                id: 'localhost'
            },
            user: {
                id: Uint8Array.from(atob(userHandle), c => c.charCodeAt(0)),
                name: username,
                displayName: displayName
            },
            pubKeyCredParams: [
                {alg: -7, type: 'public-key'}
            ],
            authenticatorSelection: {
                authenticatorAttachment: 'cross-platform'
            },
            timeout: 60000,
            attestation: 'none'
        }
    });

    if(!resp) {
        throw new Error('Missing credential response from navigator.credentials.create');
    }

    const publicKeyCredential = resp as PublicKeyCredential;

    const { id } = publicKeyCredential;
    const { clientDataJSON, attestationObject } = publicKeyCredential.response as AuthenticatorAttestationResponse;

    return {
        id,
        clientDataJson: btoa(String.fromCharCode(...new Uint8Array(clientDataJSON))),
        attestationObject: btoa(String.fromCharCode(...new Uint8Array(attestationObject)))
    };
}