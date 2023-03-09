// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Hashing Functions.

#![warn(missing_docs)]

use crate::utils::serialize_result;
use ark_bls12_381::{
	g1, g2, Bls12_381, Fq12Config, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{models::CurveConfig, pairing::Pairing, Group};
use ark_ff::{Fp12ConfigWrapper, QuadExtField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::io::Cursor;
use sp_std::vec::Vec;

/// Compute multi miller loop through arkworks
pub fn multi_miller_loop(a_vec: Vec<Vec<u8>>, b_vec: Vec<Vec<u8>>) -> Vec<u8> {
	let _g1: Vec<_> = a_vec
		.iter()
		.map(|a| {
			let cursor = Cursor::new(a);
			<ark_ec::short_weierstrass::Affine<ark_bls12_381::g1::Config> as CanonicalDeserialize>::deserialize_uncompressed(cursor)
			.map(<Bls12_381 as Pairing>::G1Prepared::from)
			.unwrap()
		})
		.collect();
	let _g2: Vec<_> = b_vec
		.iter()
		.map(|b| {
			let cursor = Cursor::new(b);
			<ark_ec::short_weierstrass::Affine<ark_bls12_381::g2::Config> as CanonicalDeserialize>::deserialize_uncompressed(cursor)
			.map(<Bls12_381 as Pairing>::G2Prepared::from)
			.unwrap()
		})
		.collect();

	let result = QuadExtField::<Fp12ConfigWrapper<Fq12Config>>::zero();

	serialize_result(result)
}

/// Compute final exponentiation through arkworks
pub fn final_exponentiation(target: Vec<u8>) -> Vec<u8> {
	let cursor = Cursor::new(target);
	let _target = <Bls12_381 as Pairing>::TargetField::deserialize_with_mode(
		cursor,
		Compress::No,
		Validate::No,
	)
	.unwrap();

	let result = QuadExtField::<Fp12ConfigWrapper<Fq12Config>>::zero();

	serialize_result(result)
}

/// Compute a scalar multiplication on G2 through arkworks
pub fn mul_projective_g2(base: Vec<u8>, scalar: Vec<u8>) -> Vec<u8> {
	let cursor = Cursor::new(base);
	let _base = G2Projective::deserialize_with_mode(cursor, Compress::No, Validate::No).unwrap();

	let cursor = Cursor::new(scalar);
	let _scalar = Vec::<u64>::deserialize_with_mode(cursor, Compress::No, Validate::No).unwrap();

	let result = G2Projective::generator();

	serialize_result(result)
}

/// Compute a scalar multiplication on G2 through arkworks
pub fn mul_projective_g1(base: Vec<u8>, scalar: Vec<u8>) -> Vec<u8> {
	let cursor = Cursor::new(base);
	let _base = G1Projective::deserialize_with_mode(cursor, Compress::No, Validate::No).unwrap();

	let cursor = Cursor::new(scalar);
	let _scalar = Vec::<u64>::deserialize_with_mode(cursor, Compress::No, Validate::No).unwrap();

	let result = G1Projective::generator();

	serialize_result(result)
}

/// Compute a scalar multiplication on G2 through arkworks
pub fn mul_affine_g1(base: Vec<u8>, scalar: Vec<u8>) -> Vec<u8> {
	let cursor = Cursor::new(base);
	let _base = G1Affine::deserialize_with_mode(cursor, Compress::No, Validate::No).unwrap();

	let cursor = Cursor::new(scalar);
	let _scalar = Vec::<u64>::deserialize_with_mode(cursor, Compress::No, Validate::No).unwrap();

	let result = G1Projective::generator();

	serialize_result(result)
}

/// Compute a scalar multiplication on G2 through arkworks
pub fn mul_affine_g2(base: Vec<u8>, scalar: Vec<u8>) -> Vec<u8> {
	let cursor = Cursor::new(base);
	let _base = G2Affine::deserialize_with_mode(cursor, Compress::No, Validate::No).unwrap();

	let cursor = Cursor::new(scalar);
	let _scalar = Vec::<u64>::deserialize_with_mode(cursor, Compress::No, Validate::No).unwrap();

	let result = G2Projective::generator();

	serialize_result(result)
}

/// Compute a multi scalar multiplication on G! through arkworks
pub fn msm_g1(bases: Vec<Vec<u8>>, scalars: Vec<Vec<u8>>) -> Vec<u8> {
	let _bases: Vec<_> = bases
		.iter()
		.map(|a| {
			let cursor = Cursor::new(a);
			<Bls12_381 as Pairing>::G1Affine::deserialize_with_mode(
				cursor,
				Compress::No,
				Validate::No,
			)
			.unwrap()
		})
		.collect();
	let _scalars: Vec<_> = scalars
		.iter()
		.map(|a| {
			let cursor = Cursor::new(a);
			<g1::Config as CurveConfig>::ScalarField::deserialize_with_mode(
				cursor,
				Compress::No,
				Validate::No,
			)
			.unwrap()
		})
		.collect();

	let result = G1Projective::generator();

	serialize_result(result)
}

/// Compute a multi scalar multiplication on G! through arkworks
pub fn msm_g2(bases: Vec<Vec<u8>>, scalars: Vec<Vec<u8>>) -> Vec<u8> {
	let _bases: Vec<_> = bases
		.iter()
		.map(|a| {
			let cursor = Cursor::new(a);
			<Bls12_381 as Pairing>::G2Affine::deserialize_with_mode(
				cursor,
				Compress::No,
				Validate::No,
			)
			.unwrap()
		})
		.collect();
	let _scalars: Vec<_> = scalars
		.iter()
		.map(|a| {
			let cursor = Cursor::new(a);
			<g2::Config as CurveConfig>::ScalarField::deserialize_with_mode(
				cursor,
				Compress::No,
				Validate::No,
			)
			.unwrap()
		})
		.collect();

	let result = G2Projective::generator();

	serialize_result(result)
}
