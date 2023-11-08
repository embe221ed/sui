// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeAll, describe, expect, it } from 'vitest';

import { parseSerializedSignature } from '../../../src/cryptography';
import {
	combinePartialSigs,
	decodeMultiSig,
	MAX_SIGNER_IN_MULTISIG,
	PubkeyWeightPair,
	toMultiSigAddress,
} from '../../../src/cryptography/multisig';
import { PublicKey } from '../../../src/cryptography/publickey';
import { Ed25519Keypair, Ed25519PublicKey } from '../../../src/keypairs/ed25519';
import { Secp256k1Keypair } from '../../../src/keypairs/secp256k1';
import { Secp256r1Keypair } from '../../../src/keypairs/secp256r1';
import { MultiSigPublicKey } from '../../../src/multisig/publickey';
import { toZkLoginPublicIdentifier, ZkLoginPublicIdentifier } from '../../../src/keypairs/zklogin/publickey';

describe('multisig address and combine sigs', () => {
	// Address and combined multisig matches rust impl: fn multisig_serde_test()
	it('combines signature to multisig', async () => {
		const VALID_SECP256K1_SECRET_KEY = [
			59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253, 102,
			39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
		];
		const secret_key = new Uint8Array(VALID_SECP256K1_SECRET_KEY);
		let k1 = Ed25519Keypair.fromSecretKey(secret_key);
		let pk1 = k1.getPublicKey();

		let k2 = Secp256k1Keypair.fromSecretKey(secret_key);
		let pk2 = k2.getPublicKey();

		let k3 = Ed25519Keypair.fromSecretKey(new Uint8Array(32).fill(0));
		let pk3 = k3.getPublicKey();

		const multiSigPublicKey = MultiSigPublicKey.fromPublicKeys({
			threshold: 3,
			publicKeys: [
				{ publicKey: pk1, weight: 1 },
				{ publicKey: pk2, weight: 2 },
				{ publicKey: pk3, weight: 3 },
			],
		});

		const data = new Uint8Array([0, 0, 0, 5, 72, 101, 108, 108, 111]);

		const sig1 = await k1.signPersonalMessage(data);
		const sig2 = await k2.signPersonalMessage(data);
		const sig3 = await k3.signPersonalMessage(data);

		expect(multiSigPublicKey.toSuiAddress()).toEqual(
			'0x37b048598ca569756146f4e8ea41666c657406db154a31f11bb5c1cbaf0b98d7',
		);

		let multisig = multiSigPublicKey.combinePartialSignatures([sig1.signature, sig2.signature]);
		expect(multisig).toEqual(
			'AwIANe9gJJmT5m1UvpV8Hj7nOyif76rS5Zgg1bi7VApts+KwtSc2Bg8WJ6LBfGnZKugrOqtQsk5d2Q+IMRLD4hYmBQFYlrlXc01/ZSdgwSD3eGEdm6kxwtOwAvTWdb2wNZP2Hnkgrh+indYN4s2Qd99iYCz+xsY6aT5lpOBsDZb2x9LyAwADAFriILSy9l6XfBLt5hV5/1FwtsIsAGFow3tefGGvAYCDAQECHRUjB8a3Kw7QQYsOcM2A5/UpW42G9XItP1IT+9I5TzYCADtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdopAwMA',
		);

		let decoded = decodeMultiSig(multisig);
		expect(decoded).toEqual([
			{
				signature: parseSerializedSignature((await k1.signPersonalMessage(data)).signature)
					.signature,
				signatureScheme: k1.getKeyScheme(),
				pubKey: pk1,
				weight: 1,
			},
			{
				signature: parseSerializedSignature((await k2.signPersonalMessage(data)).signature)
					.signature,
				signatureScheme: k2.getKeyScheme(),
				pubKey: pk2,
				weight: 2,
			},
		]);

		const parsed = parseSerializedSignature(multisig);
		const publicKey = new MultiSigPublicKey(parsed.multisig!.multisig_pk);
		// multisig (sig1 + sig2 weight 1+2 >= threshold ) verifies ok
		expect(await publicKey.verifyPersonalMessage(data, multisig)).toEqual(true);

		let multisig2 = parseSerializedSignature(
			multiSigPublicKey.combinePartialSignatures([sig3.signature]),
		);

		// multisig (sig3 only weight = 3 >= threshold) verifies ok
		expect(
			await multiSigPublicKey.verifyPersonalMessage(data, multisig2.serializedSignature),
		).toEqual(true);

		let multisig3 = parseSerializedSignature(
			multiSigPublicKey.combinePartialSignatures([sig2.signature]),
		);

		// multisig (sig2 only weight = 2 < threshold) verify fails

		expect(
			await new MultiSigPublicKey(multisig3.multisig!.multisig_pk).verifyPersonalMessage(
				data,
				multisig3.serializedSignature,
			),
		).toEqual(false);
	});
});

describe('Multisig', () => {
	let k1: Ed25519Keypair,
		pk1: Ed25519PublicKey,
		k2: Secp256k1Keypair,
		pk2: PublicKey,
		k3: Secp256r1Keypair,
		pk3: PublicKey,
		pk4: PublicKey,
		pk5: PublicKey;

	beforeAll(() => {
		const VALID_SECP256K1_SECRET_KEY = [
			59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253, 102,
			39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
		];

		const VALID_SECP256R1_SECRET_KEY = [
			66, 37, 141, 205, 161, 76, 241, 17, 198, 2, 184, 151, 27, 140, 200, 67, 233, 30, 70, 202, 144,
			81, 81, 192, 39, 68, 166, 176, 23, 230, 147, 22,
		];

		const secret_key_k1 = new Uint8Array(VALID_SECP256K1_SECRET_KEY);
		const secret_key_r1 = new Uint8Array(VALID_SECP256R1_SECRET_KEY);

		k1 = Ed25519Keypair.fromSecretKey(secret_key_k1);
		pk1 = k1.getPublicKey();

		k2 = Secp256k1Keypair.fromSecretKey(secret_key_k1);
		pk2 = k2.getPublicKey();

		k3 = Secp256r1Keypair.fromSecretKey(secret_key_r1);
		pk3 = k3.getPublicKey();

		pk4 = toZkLoginPublicIdentifier("https://id.twitch.tv/oauth2", "20794788559620669596206457022966176986688727876128223628113916380927502737911");
		pk5 = toZkLoginPublicIdentifier("https://id.twitch.tv/oauth2", "380704556853533152350240698167704405529973457670972223618755249929828551006");
	});

	it('`toMultiSigAddress()` should derive a multisig address correctly', async () => {
		const pubkeyWeightPairs: PubkeyWeightPair[] = [
			{
				pubKey: pk1,
				weight: 1,
			},
			{
				pubKey: pk2,
				weight: 2,
			},
			{
				pubKey: pk3,
				weight: 3,
			},
		];

		const multisigAddress = toMultiSigAddress(pubkeyWeightPairs, 3);

		expect(multisigAddress).toEqual(
			'0x8ee027fe556a3f6c0a23df64f090d2429fec0bb21f55594783476e81de2dec27',
		);
	});
	
	it('`toMultiSigAddress()` with zklogin identifiers', async () => {
		const pubkeyWeightPairs: PubkeyWeightPair[] = [
			{
				pubKey: pk4,
				weight: 1,
			},
			{
				pubKey: pk5,
				weight: 1,
			}
		];

		const multisigAddress = toMultiSigAddress(pubkeyWeightPairs, 1);

		expect(multisigAddress).toEqual(
			'0x77a9fbf3c695d78dd83449a81a9e70aa79a77dbfd6fb72037bf09201c12052cd',
		);
	});

	it('`toMultiSigAddress()` should throw an error when exceeding the max number of signers', async () => {
		const pubkeyWeightPairs: PubkeyWeightPair[] = new Array(MAX_SIGNER_IN_MULTISIG + 1).fill({
			pubKey: pk1,
			weight: 1,
		});

		expect(() => toMultiSigAddress(pubkeyWeightPairs, 3)).toThrowError(
			new Error(`Max number of signers in a multisig is ${MAX_SIGNER_IN_MULTISIG}`),
		);
	});

	it('`combinePartialSigs()` should combine with different signatures into a single multisig correctly', async () => {
		const pubkeyWeightPairs: PubkeyWeightPair[] = [
			{
				pubKey: pk1,
				weight: 1,
			},
			{
				pubKey: pk2,
				weight: 2,
			},
			{
				pubKey: pk3,
				weight: 3,
			},
		];

		const data = new Uint8Array([0, 0, 0, 5, 72, 101, 108, 108, 111]);

		const sig1 = await k1.signPersonalMessage(data);
		const sig2 = await k2.signPersonalMessage(data);

		const multisig = combinePartialSigs([sig1.signature, sig2.signature], pubkeyWeightPairs, 3);

		expect(multisig).toEqual(
			'AwIANe9gJJmT5m1UvpV8Hj7nOyif76rS5Zgg1bi7VApts+KwtSc2Bg8WJ6LBfGnZKugrOqtQsk5d2Q+IMRLD4hYmBQFYlrlXc01/ZSdgwSD3eGEdm6kxwtOwAvTWdb2wNZP2Hnkgrh+indYN4s2Qd99iYCz+xsY6aT5lpOBsDZb2x9LyAwADAFriILSy9l6XfBLt5hV5/1FwtsIsAGFow3tefGGvAYCDAQECHRUjB8a3Kw7QQYsOcM2A5/UpW42G9XItP1IT+9I5TzYCAgInMis6iRoKKA1rwfssuyPSj1SQb9ZAf190H23vV2JgmgMDAA==',
		);

		const decoded = decodeMultiSig(multisig);
		expect(decoded).toEqual([
			{
				signature: parseSerializedSignature((await k1.signPersonalMessage(data)).signature)
					.signature,
				signatureScheme: k1.getKeyScheme(),
				pubKey: pk1,
				weight: 1,
			},
			{
				signature: parseSerializedSignature((await k2.signPersonalMessage(data)).signature)
					.signature,
				signatureScheme: k2.getKeyScheme(),
				pubKey: pk2,
				weight: 2,
			},
		]);
	});

	it('`combinePartialSigs()` with zklogin sigs', async () => {
		const pubkeyWeightPairs: PubkeyWeightPair[] = [
			{
				pubKey: pk1, // check this matches rust
				weight: 1,
			},
			{
				pubKey: pk4,
				weight: 1,
			}
		];

		const data = new Uint8Array([0, 0, 1, 0, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 0, 1, 0, 0, 185, 192, 120, 10, 57, 67, 205, 225, 58, 36, 9, 191, 26, 111, 6, 174, 96, 176, 223, 242, 178, 243, 115, 38, 12, 246, 39, 170, 79, 67, 165, 136, 1, 155, 7, 129, 95, 4, 73, 126, 46, 5, 210, 44, 172, 58, 160, 97, 65, 11, 32, 134, 140, 198, 25, 21, 76, 66, 161, 198, 27, 233, 144, 39, 23, 1, 0, 0, 0, 0, 0, 0, 0, 32, 150, 112, 237, 74, 86, 213, 113, 238, 108, 228, 72, 57, 166, 60, 119, 111, 150, 200, 19, 112, 160, 159, 133, 16, 12, 101, 177, 174, 225, 236, 145, 235, 185, 192, 120, 10, 57, 67, 205, 225, 58, 36, 9, 191, 26, 111, 6, 174, 96, 176, 223, 242, 178, 243, 115, 38, 12, 246, 39, 170, 79, 67, 165, 136, 1, 0, 0, 0, 0, 0, 0, 0, 16, 39, 0, 0, 0, 0, 0, 0, 0]);

		const sig1 = await k1.signTransactionBlock(data);
		const zklogin_sig = "";
		const multisig = combinePartialSigs([sig1.signature, zklogin_sig], pubkeyWeightPairs, 1);

		expect(multisig).toEqual(
			'AwEDA00xNzMxODA4OTEyNTk1MjQyMTczNjM0MjI2MzcxNzkzMjcxOTQzNzcxNzg0NDI4MjQxMDE4Nzk1Nzk4NDc1MTkzOTk0Mjg5ODI1MTI1ME0xMTM3Mzk2NjY0NTQ2OTEyMjU4MjA3NDA4MjI5NTk4NTM4ODI1ODg0MDY4MTYxODI2ODU5Mzk3NjY5NzMyNTg5MjI4MDkxNTY4MTIwNwExAwJMNTkzOTg3MTE0NzM0ODgzNDk5NzM2MTcyMDEyMjIzODk4MDE3NzE1MjMwMzI3NDMxMTA0NzI0OTkwNTk0MjM4NDkxNTc2ODY5MDg5NUw0NTMzNTY4MjcxMTM0Nzg1Mjc4NzMxMjM0NTcwMzYxNDgyNjUxOTk2NzQwNzkxODg4Mjg1ODY0OTY2ODg0MDMyNzE3MDQ5ODExNzA4Ak0xMDU2NDM4NzI4NTA3MTU1NTQ2OTc1Mzk5MDY2MTQxMDg0MDExODYzNTkyNTQ2NjU5NzAzNzAxODA1ODc3MDA0MTM0NzUxODQ2MTM2OE0xMjU5NzMyMzU0NzI3NzU3OTE0NDY5ODQ5NjM3MjI0MjYxNTM2ODA4NTgwMTMxMzM0MzE1NTczNTUxMTMzMDAwMzg4NDc2Nzk1Nzg1NAIBMQEwA00xNTc5MTU4OTQ3MjU1NjgyNjI2MzIzMTY0NDcyODg3MzMzNzYyOTAxNTI2OTk4NDY5OTQwNDA3MzYyMzYwMzM1MjUzNzY3ODgxMzE3MUw0NTQ3ODY2NDk5MjQ4ODgxNDQ5Njc2MTYxMTU4MDI0NzQ4MDYwNDg1MzczMjUwMDI5NDIzOTA0MTEzMDE3NDIyNTM5MDM3MTYyNTI3ATExd2lhWE56SWpvaWFIUjBjSE02THk5cFpDNTBkMmwwWTJndWRIWXZiMkYxZEdneUlpdwIyZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0lzSW10cFpDSTZJakVpZlFNMjA3OTQ3ODg1NTk2MjA2Njk1OTYyMDY0NTcwMjI5NjYxNzY5ODY2ODg3Mjc4NzYxMjgyMjM2MjgxMTM5MTYzODA5Mjc1MDI3Mzc5MTEKAAAAAAAAAGEAEemRDkm/GpuoIq2qH0zRTlzejeXrYHoAtU7EyrqexzTLcmVjwZ/Vmg8D3vp2ibrLckYFROyvLprF+odxWu1EDLnG7hYw7z5xEUSmSNsGu7IoT3J0z77lP/zuUDzBpJIAAgACAA19qzWMja2qTvoASadbB0NlVbEKNoIZu2gPcFcTSdd1AQM8G2h0dHBzOi8vaWQudHdpdGNoLnR2L29hdXRoMi35buhGoP8xt7S3eQrWUWMfadbd+EaL1Up//rhxYmH3AQEA',
		);

		const decoded = decodeMultiSig(multisig);
		expect(decoded).toEqual([
			{
				signature: '',
				signatureScheme: 'ZkLogin',
				pubKey: pk4,
				weight: 1,
			},
			{
				signature: parseSerializedSignature((await k1.signPersonalMessage(data)).signature)
					.signature,
				signatureScheme: k2.getKeyScheme(),
				pubKey: pk2,
				weight: 2,
			},
		]);
	});

	it('`decodeMultiSig()` should decode a multisig signature correctly', async () => {
		const pubkeyWeightPairs: PubkeyWeightPair[] = [
			{
				pubKey: pk1,
				weight: 1,
			},
			{
				pubKey: pk2,
				weight: 2,
			},
			{
				pubKey: pk3,
				weight: 3,
			},
		];

		const data = new Uint8Array([0, 0, 0, 5, 72, 101, 108, 108, 111]);

		const sig1 = await k1.signPersonalMessage(data);
		const sig2 = await k2.signPersonalMessage(data);
		const sig3 = await k3.signPersonalMessage(data);

		const multisig = combinePartialSigs(
			[sig1.signature, sig2.signature, sig3.signature],
			pubkeyWeightPairs,
			3,
		);

		const decoded = decodeMultiSig(multisig);
		expect(decoded).toEqual([
			{
				signature: parseSerializedSignature((await k1.signPersonalMessage(data)).signature)
					.signature,
				signatureScheme: k1.getKeyScheme(),
				pubKey: pk1,
				weight: 1,
			},
			{
				signature: parseSerializedSignature((await k2.signPersonalMessage(data)).signature)
					.signature,
				signatureScheme: k2.getKeyScheme(),
				pubKey: pk2,
				weight: 2,
			},
			{
				signature: parseSerializedSignature((await k3.signPersonalMessage(data)).signature)
					.signature,
				signatureScheme: k3.getKeyScheme(),
				pubKey: pk3,
				weight: 3,
			},
		]);
	});

	it('`decodeMultiSig()` should handle invalid parameters', async () => {
		const data = new Uint8Array([0, 0, 0, 5, 72, 101, 108, 108, 111]);

		const sig1 = await k1.signPersonalMessage(data);

		expect(() => decodeMultiSig(sig1.signature)).toThrowError(new Error('Invalid MultiSig flag'));

		expect(() => decodeMultiSig('')).toThrowError(new Error('Invalid MultiSig flag'));

		expect(() => decodeMultiSig('Invalid string')).toThrowError(new Error('Invalid MultiSig flag'));
	});
});
