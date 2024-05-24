/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SIGNATURE_H__
#define SIGNATURE_H__


#include "Gost.h"


bool bn2buf (const BIGNUM * bn, uint8_t * buf, size_t len)
{
	int offset = len - BN_num_bytes (bn);
	if (offset < 0) return false;
	BN_bn2bin (bn, buf + offset);
	memset (buf, 0, offset);
	return true;
}

namespace i2p
{
namespace crypto
{
	class Verifier
	{
		public:

			virtual ~Verifier () {};
			virtual bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const = 0;
			virtual size_t GetPublicKeyLen () const = 0;
			virtual size_t GetSignatureLen () const = 0;
			virtual size_t GetPrivateKeyLen () const { return GetSignatureLen ()/2; };
			virtual void SetPublicKey (const uint8_t * signingKey) = 0;
	};

	class Signer
	{
		public:

			virtual ~Signer () {};
			virtual void Sign (const uint8_t * buf, int len, uint8_t * signature) const = 0;
	};

	// ГОСТ Р 34.11
	struct GOSTR3411_256_Hash
	{
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			GOSTR3411_2012_256 (buf, len, digest);
		}

		enum { hashLen = 32 };
	};

	struct GOSTR3411_512_Hash
	{
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			GOSTR3411_2012_512 (buf, len, digest);
		}

		enum { hashLen = 64 };
	};

	// ГОСТ Р 34.10
	const size_t GOSTR3410_256_PUBLIC_KEY_LENGTH = 64;
	const size_t GOSTR3410_512_PUBLIC_KEY_LENGTH = 128;

	template<typename Hash>
	class GOSTR3410Verifier: public Verifier
	{
		public:

			enum { keyLen = Hash::hashLen };

			GOSTR3410Verifier (GOSTR3410ParamSet paramSet):
				m_ParamSet (paramSet), m_PublicKey (nullptr)
			{
			}

			void SetPublicKey (const uint8_t * signingKey)
			{
				BIGNUM * x = BN_bin2bn (signingKey, GetPublicKeyLen ()/2, NULL);
				BIGNUM * y = BN_bin2bn (signingKey + GetPublicKeyLen ()/2, GetPublicKeyLen ()/2, NULL);
				m_PublicKey = GetGOSTR3410Curve (m_ParamSet)->CreatePoint (x, y);
				BN_free (x); BN_free (y);
			}
			~GOSTR3410Verifier ()
			{
				if (m_PublicKey) EC_POINT_free (m_PublicKey);
			}

			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				BIGNUM * d = BN_bin2bn (digest, Hash::hashLen, nullptr);
				BIGNUM * r = BN_bin2bn (signature, GetSignatureLen ()/2, NULL);
				BIGNUM * s = BN_bin2bn (signature + GetSignatureLen ()/2, GetSignatureLen ()/2, NULL);
				bool ret = GetGOSTR3410Curve (m_ParamSet)->Verify (m_PublicKey, d, r, s);
				BN_free (d); BN_free (r); BN_free (s);
				return ret;
			}

			size_t GetPublicKeyLen () const { return keyLen*2; }
			size_t GetSignatureLen () const { return keyLen*2; }

		private:

			GOSTR3410ParamSet m_ParamSet;
			EC_POINT * m_PublicKey;
	};

	template<typename Hash>
	class GOSTR3410Signer: public Signer
	{
		public:

			enum { keyLen = Hash::hashLen };

			GOSTR3410Signer (GOSTR3410ParamSet paramSet, const uint8_t * signingPrivateKey):
				m_ParamSet (paramSet)
			{
				m_PrivateKey = BN_bin2bn (signingPrivateKey, keyLen, nullptr);
			}
			~GOSTR3410Signer () { BN_free (m_PrivateKey); }

			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				BIGNUM * d = BN_bin2bn (digest, Hash::hashLen, nullptr);
				BIGNUM * r = BN_new (), * s = BN_new ();
				GetGOSTR3410Curve (m_ParamSet)->Sign (m_PrivateKey, d, r, s);
				bn2buf (r, signature, keyLen);
				bn2buf (s, signature + keyLen, keyLen);
				BN_free (d); BN_free (r); BN_free (s);
			}

		private:

			GOSTR3410ParamSet m_ParamSet;
			BIGNUM * m_PrivateKey;
	};
	template<typename Hash>
	inline void CreateGOSTR3410RandomKeys (GOSTR3410ParamSet paramSet, uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		const auto& curve = GetGOSTR3410Curve (paramSet);
		auto keyLen = Hash::hashLen;
		RAND_bytes (signingPrivateKey, keyLen);
		BIGNUM * priv = BN_bin2bn (signingPrivateKey, keyLen, nullptr);

		auto pub = curve->MulP (priv);
		BN_free (priv);
		BIGNUM * x = BN_new (), * y = BN_new ();
		curve->GetXY (pub, x, y);
		EC_POINT_free (pub);
		bn2buf (x, signingPublicKey, keyLen);
		bn2buf (y, signingPublicKey + keyLen, keyLen);
		BN_free (x); BN_free (y);
	}

	typedef GOSTR3410Verifier<GOSTR3411_256_Hash> GOSTR3410_256_Verifier;
	typedef GOSTR3410Signer<GOSTR3411_256_Hash> GOSTR3410_256_Signer;
	typedef GOSTR3410Verifier<GOSTR3411_512_Hash> GOSTR3410_512_Verifier;
	typedef GOSTR3410Signer<GOSTR3411_512_Hash> GOSTR3410_512_Signer;
}
}

#endif
