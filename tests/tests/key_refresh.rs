#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod generic {
    use generic_ec::{hash_to_curve::FromHash, Point};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::{security_level::ReasonablySecure, ExecutionId};

    #[test_case::case(3; "n3")]
    #[test_case::case(5; "n5")]
    #[tokio::test]
    async fn key_refresh_works<E: generic_ec::Curve>(n: u16)
    where
        generic_ec::Scalar<E>: FromHash,
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = rand_dev::DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E>(None, n)
            .expect("retrieve cached shares");
        let mut primes = cggmp21_tests::CACHED_PRIMES.iter();

        // Perform refresh

        let refresh_execution_id: [u8; 32] = rng.gen();
        let refresh_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&refresh_execution_id);
        let mut simulation =
            Simulation::<cggmp21::key_refresh::Msg<E, Sha256, ReasonablySecure>>::new();
        let outputs = shares.iter().map(|share| {
            let party = simulation.add_party();
            let refresh_execution_id = refresh_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
            let pregenerated_data = primes.next().expect("Can't fetch primes");
            async move {
                cggmp21::key_refresh(share, pregenerated_data)
                    .set_execution_id(refresh_execution_id)
                    .start(&mut party_rng, party)
                    .await
            }
        });

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        // validate key shares

        for (i, key_share) in key_shares.iter().enumerate() {
            let i = i as u16;
            assert_eq!(i, key_share.core.i);
            assert_eq!(
                key_share.core.shared_public_key,
                key_shares[0].core.shared_public_key
            );
            assert_eq!(key_share.core.rid.as_ref(), key_shares[0].core.rid.as_ref());
            assert_eq!(
                key_share.core.public_shares,
                key_shares[0].core.public_shares
            );
            assert_eq!(
                Point::<E>::generator() * &key_share.core.x,
                key_share.core.public_shares[usize::from(i)]
            );
        }
        assert_eq!(
            key_shares[0].core.shared_public_key,
            key_shares[0].core.public_shares.iter().sum::<Point<E>>()
        );
        for key_share in &key_shares {
            assert_eq!(
                key_share.core.shared_public_key,
                shares[0].core.shared_public_key
            );
        }

        // attempt to sign with new shares and verify the signature

        let signing_execution_id = ExecutionId::<E, ReasonablySecure>::from_bytes(&[228; 32]);
        let mut simulation = Simulation::<cggmp21::signing::Msg<E, Sha256>>::new();
        let message_to_sign = cggmp21::signing::Message::new::<Sha256>(&[42; 100]);
        let participants = &(0..n).collect::<Vec<_>>();
        let outputs = key_shares.iter().map(|share| {
            let party = simulation.add_party();
            let signing_execution_id = signing_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
            async move {
                cggmp21::signing(share.core.i, &participants, share)
                    .set_execution_id(signing_execution_id)
                    .sign(&mut party_rng, party, message_to_sign)
                    .await
            }
        });
        let signatures = futures::future::try_join_all(outputs)
            .await
            .expect("signing failed");

        for signature in &signatures {
            signature
                .verify(&key_shares[0].core.shared_public_key, &message_to_sign)
                .expect("signature is not valid");
        }
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
}
