// See WebAuthnPublicKeyRegistration in the backend
type WebAuthnPublicKeyRegistration = {
    id: string,
    clientDataJson: string,
    attestationObject: string
};

export async function registerSecurityKey(challenge: string, name: string, userHandle: string, username: string, displayName: string): Promise<WebAuthnPublicKeyRegistration> {
    const resp = await navigator.credentials.create({
        publicKey: {
            challenge: fromBase64Url(challenge),
            rp: {
                name,
                // TODO MRB: get this from client config?
                id: 'localhost'
            },
            user: {
                id: fromBase64Url(userHandle),
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
        clientDataJson: toBase64Url(clientDataJSON),
        attestationObject: toBase64Url(attestationObject)
    };
}

// Would use Buffer here but they don't support base64url yet
// https://github.com/feross/buffer/pull/314
function fromBase64Url(input: string): Uint8Array {
    return Uint8Array.from(
        atob(
            input
                .replaceAll('-', '+')
                .replaceAll('_', '/')
        ),
        c => c.charCodeAt(0)
    );
}

function toBase64Url(input: ArrayBuffer): string {
    return btoa(
        String.fromCharCode(
            ...new Uint8Array(input)
        )
    ).replaceAll('+', '-')
        .replaceAll('/', '_')
}