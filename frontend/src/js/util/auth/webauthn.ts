// See WebAuthnPublicKeyRegistration in the backend
type WebAuthnPublicKeyRegistration = {
    id: string,
    clientDataJson: string,
    attestationObject: string
};

// See WebAuthnChallengeResponse in the backend
type WebAuthnChallengeResponse = {
    id: string,
    userHandle: string | null,
    clientDataJson: string,
    authenticatorData: string,
    signature: string
}

// TODO MRB: test how the UI reacts to and recovers from a timeout
const timeout = 60000

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
            timeout,
            attestation: 'none'
        }
    });

    if(!resp) {
        throw new Error('Missing credential response from navigator.credentials.create');
    }

    const publicKeyCredential = resp as PublicKeyCredential;
    const { clientDataJSON, attestationObject } = publicKeyCredential.response as AuthenticatorAttestationResponse;

    return {
        id: publicKeyCredential.id,
        clientDataJson: toBase64Url(clientDataJSON),
        attestationObject: toBase64Url(attestationObject)
    };
}

export async function checkSecurityKey(challenge: string, credentialIds: string[]): Promise<WebAuthnChallengeResponse> {
    const resp = await navigator.credentials.get({
        publicKey: {
            challenge: fromBase64Url(challenge),
            allowCredentials: credentialIds.map(id => ({
                id: fromBase64Url(id),
                type: 'public-key'
            })),
            timeout
        }
    });

    if(!resp) {
        throw new Error('Missing credential response from navigator.credentials.get');
    }

    const publicKeyCredential = resp as PublicKeyCredential;
    const { userHandle, clientDataJSON, authenticatorData, signature } = publicKeyCredential.response as AuthenticatorAssertionResponse;

    return {
        id: publicKeyCredential.id,
        userHandle: userHandle ? toBase64Url(userHandle) : null,
        clientDataJson: toBase64Url(clientDataJSON),
        authenticatorData: toBase64Url(authenticatorData),
        signature: toBase64Url(signature)
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