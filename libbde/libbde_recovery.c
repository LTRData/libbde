/*
 * Recovery functions
 *
 * Copyright (C) 2011-2025, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <byte_stream.h>
#include <memory.h>
#include <narrow_string.h>
#include <types.h>

#include "libbde_libcaes.h"
#include "libbde_libcerror.h"
#include "libbde_libcnotify.h"
#include "libbde_libfvalue.h"
#include "libbde_libhmac.h"
#include "libbde_recovery.h"

/* Calculates the SHA256 hash of an UTF-8 formatted recovery password
 * Returns 1 if successful, 0 if recovery password is invalid or -1 on error
 */
int libbde_utf8_recovery_password_calculate_hash(
     const uint8_t *utf8_string,
     size_t utf8_string_length,
     uint8_t *recovery_password_hash,
     size_t recovery_password_hash_size,
     libcerror_error_t **error )
{
	uint8_t binary_recovery_password[ 16 ];

	libfvalue_split_utf8_string_t *split_string = NULL;
	uint8_t *string_segment                     = NULL;
	static char *function                       = "libbde_utf8_recovery_password_calculate_hash";
	size_t string_segment_index                 = 0;
	size_t string_segment_size                  = 0;
	uint64_t value_64bit                        = 0;
	int number_of_segments                      = 0;
	int result                                  = 0;
	int segment_index                           = 0;

	if( recovery_password_hash == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid recovery password hash.",
		 function );

		return( -1 );
	}
	if( recovery_password_hash_size != 32 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: recovery password hash size value out of bounds.",
		 function );

		return( -1 );
	}
	if( libfvalue_utf8_string_split(
	     utf8_string,
	     utf8_string_length + 1,
	     (uint8_t) '-',
 	     &split_string,
 	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to split string.",
		 function );

		goto on_error;
	}
	if( libfvalue_split_utf8_string_get_number_of_segments(
	     split_string,
	     &number_of_segments,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of segments in split string.",
		 function );

		goto on_error;
	}
	/* The recovery password consists of 8 segments
	 */
	if( number_of_segments == 8 )
	{
		for( segment_index = 0;
		     segment_index < number_of_segments;
		     segment_index++ )
		{
			if( libfvalue_split_utf8_string_get_segment_by_index(
			     split_string,
			     segment_index,
			     &string_segment,
			     &string_segment_size,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve segment: %d from split string.",
				 function,
				 segment_index );

				goto on_error;
			}
			string_segment_index = 0;

			if( libfvalue_utf8_string_with_index_copy_to_integer(
			     string_segment,
			     string_segment_size,
			     &string_segment_index,
			     &value_64bit,
			     16,
			     LIBFVALUE_INTEGER_FORMAT_TYPE_DECIMAL_UNSIGNED,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to determine binary value for segment: %d from split string.",
				 function,
				 segment_index );

				goto on_error;
			}
			/* A recovery password segment should be dividable by 11
			 */
			if( ( value_64bit % 11 ) != 0 )
			{
				break;
			}
			value_64bit /= 11;

			/* A recovery password segment / 11 should be <= 65535 (0xffff)
			 */
			if( value_64bit > (uint64_t) UINT16_MAX )
			{
				break;
			}
			byte_stream_copy_from_uint16_little_endian(
			 &( binary_recovery_password[ segment_index * 2 ] ),
			 value_64bit );
		}
		result = 1;
	}
	if( libfvalue_split_utf8_string_free(
	     &split_string,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free split string.",
		 function );

		goto on_error;
	}
	if( result == 1 )
	{
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: binary recovery password:\n",
			 function );
			libcnotify_print_data(
			 binary_recovery_password,
			 16,
			 0 );
		}
#endif
		if( libhmac_sha256_calculate(
		     binary_recovery_password,
		     16,
		     recovery_password_hash,
		     recovery_password_hash_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to calculate recovery password hash.",
			 function );

			goto on_error;
		}
		if( memory_set(
		     binary_recovery_password,
		     0,
		     16 ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_SET_FAILED,
			 "%s: unable to clear binary recovery password.",
			 function );

			goto on_error;
		}
	}
	return( result );

on_error:
	if( split_string != NULL )
	{
		libfvalue_split_utf8_string_free(
		 &split_string,
		 NULL );
	}
	memory_set(
	 binary_recovery_password,
	 0,
	 16 );

	return( -1 );
}

/* Calculates the SHA256 hash of an UTF-16 formatted recovery password
 * Returns 1 if successful, 0 if recovery password is invalid or -1 on error
 */
int libbde_utf16_recovery_password_calculate_hash(
     const uint16_t *utf16_string,
     size_t utf16_string_length,
     uint8_t *recovery_password_hash,
     size_t recovery_password_hash_size,
     libcerror_error_t **error )
{
	uint8_t binary_recovery_password[ 16 ];

	libfvalue_split_utf16_string_t *split_string = NULL;
	uint16_t *string_segment                     = NULL;
	static char *function                        = "libbde_utf16_recovery_password_calculate_hash";
	size_t string_segment_index                  = 0;
	size_t string_segment_size                   = 0;
	uint64_t value_64bit                         = 0;
	int number_of_segments                       = 0;
	int result                                   = 0;
	int segment_index                            = 0;

	if( recovery_password_hash == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid recovery password hash.",
		 function );

		return( -1 );
	}
	if( recovery_password_hash_size != 32 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: recovery password hash size value out of bounds.",
		 function );

		return( -1 );
	}
	if( libfvalue_utf16_string_split(
	     utf16_string,
	     utf16_string_length + 1,
	     (uint16_t) '-',
 	     &split_string,
 	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to split string.",
		 function );

		goto on_error;
	}
	if( libfvalue_split_utf16_string_get_number_of_segments(
	     split_string,
	     &number_of_segments,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of segments in split string.",
		 function );

		goto on_error;
	}
	/* The recovery password consists of 8 segments
	 */
	if( number_of_segments == 8 )
	{
		for( segment_index = 0;
		     segment_index < number_of_segments;
		     segment_index++ )
		{
			if( libfvalue_split_utf16_string_get_segment_by_index(
			     split_string,
			     segment_index,
			     &string_segment,
			     &string_segment_size,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve segment: %d from split string.",
				 function,
				 segment_index );

				goto on_error;
			}
			string_segment_index = 0;

			if( libfvalue_utf16_string_with_index_copy_to_integer(
			     string_segment,
			     string_segment_size,
			     &string_segment_index,
			     &value_64bit,
			     16,
			     LIBFVALUE_INTEGER_FORMAT_TYPE_DECIMAL_UNSIGNED,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to determine binary value for segment: %d from split string.",
				 function,
				 segment_index );

				goto on_error;
			}
			/* A recovery password segment should be dividable by 11
			 */
			if( ( value_64bit % 11 ) != 0 )
			{
				break;
			}
			value_64bit /= 11;

			/* A recovery password segment / 11 should be <= 65535 (0xffff)
			 */
			if( value_64bit > (uint64_t) UINT16_MAX )
			{
				break;
			}
			byte_stream_copy_from_uint16_little_endian(
			 &( binary_recovery_password[ segment_index * 2 ] ),
			 value_64bit );
		}
		result = 1;
	}
	if( libfvalue_split_utf16_string_free(
	     &split_string,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free split string.",
		 function );

		goto on_error;
	}
	if( result == 1 )
	{
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: binary recovery password:\n",
			 function );
			libcnotify_print_data(
			 binary_recovery_password,
			 16,
			 0 );
		}
#endif
		if( libhmac_sha256_calculate(
		     binary_recovery_password,
		     16,
		     recovery_password_hash,
		     recovery_password_hash_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to calculate recovery password hash.",
			 function );

			goto on_error;
		}
		if( memory_set(
		     binary_recovery_password,
		     0,
		     16 ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_SET_FAILED,
			 "%s: unable to clear binary recovery password.",
			 function );

			goto on_error;
		}
	}
	return( result );

on_error:
	if( split_string != NULL )
	{
		libfvalue_split_utf16_string_free(
		 &split_string,
		 NULL );
	}
	memory_set(
	 binary_recovery_password,
	 0,
	 16 );

	return( -1 );
}

/* Recovers the recovery password from metadata using the plain VMK bytes
 * Returns 1 if successful, 0 if the recovery password VMK entry is not present or -1 on error
 */
int libbde_recovery_password_from_vmk(
     libbde_metadata_t *metadata,
     const uint8_t *vmk_bytes,
     size_t vmk_bytes_size,
     uint8_t *recovery_password,
     size_t recovery_password_size,
     libcerror_error_t **error )
{
	uint8_t *unencrypted_data      = NULL;
	libcaes_context_t *aes_context = NULL;
	static char *function          = "libbde_recovery_password_from_vmk";
	size_t unencrypted_data_size   = 0;
	uint16_t block_value           = 0;
	uint32_t formatted_block       = 0;
	int block_index                = 0;
	int print_count                = 0;

	if( metadata == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid metadata.",
		 function );

		return( -1 );
	}
	if( metadata->recovery_password_volume_master_key == NULL )
	{
		return( 0 );
	}
	if( metadata->recovery_password_volume_master_key->aes_ccm_encrypted_key == NULL )
	{
		return( 0 );
	}
	if( vmk_bytes == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid VMK bytes.",
		 function );

		return( -1 );
	}
	if( vmk_bytes_size < 32 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid VMK bytes value too small.",
		 function );

		return( -1 );
	}
	if( recovery_password == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid recovery password.",
		 function );

		return( -1 );
	}
	if( recovery_password_size < 56 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid recovery password value too small.",
		 function );

		return( -1 );
	}
	unencrypted_data_size = metadata->recovery_password_volume_master_key->aes_ccm_encrypted_key->data_size;

	if( ( unencrypted_data_size < 28 )
	 || ( unencrypted_data_size > MEMORY_MAXIMUM_ALLOCATION_SIZE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid recovery password VMK - AES-CCM encrypted key data size value out of bounds.",
		 function );

		return( -1 );
	}
	unencrypted_data = (uint8_t *) memory_allocate(
	                                unencrypted_data_size );

	if( unencrypted_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create unencrypted data.",
		 function );

		return( -1 );
	}
	if( memory_set(
	     unencrypted_data,
	     0,
	     unencrypted_data_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear unencrypted data.",
		 function );

		goto on_error;
	}
	if( libcaes_context_initialize(
	     &aes_context,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable initialize AES context.",
		 function );

		goto on_error;
	}
	if( libcaes_context_set_key(
	     aes_context,
	     LIBCAES_CRYPT_MODE_ENCRYPT,
	     vmk_bytes,
	     256,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set encryption key in AES context.",
		 function );

		goto on_error;
	}
	if( libcaes_crypt_ccm(
	     aes_context,
	     LIBCAES_CRYPT_MODE_DECRYPT,
	     metadata->recovery_password_volume_master_key->aes_ccm_encrypted_key->nonce,
	     12,
	     metadata->recovery_password_volume_master_key->aes_ccm_encrypted_key->data,
	     metadata->recovery_password_volume_master_key->aes_ccm_encrypted_key->data_size,
	     unencrypted_data,
	     unencrypted_data_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
		 LIBCERROR_ENCRYPTION_ERROR_ENCRYPT_FAILED,
		 "%s: unable to decrypt data.",
		 function );

		goto on_error;
	}
	if( libcaes_context_free(
	     &aes_context,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable free context.",
		 function );

		goto on_error;
	}
	for( block_index = 0;
	     block_index < 8;
	     block_index++ )
	{
		byte_stream_copy_to_uint16_little_endian(
		 &( unencrypted_data[ 0x18 + ( block_index * 2 ) ] ),
		 block_value );

		formatted_block = (uint32_t) block_value * 11;

		if( block_index < 7 )
		{
			/* Use size 8 so sprintf_s (MSVC) has room for the 7 visible
			 * characters ("XXXXXX-") plus its required null terminator.
			 * The null will be overwritten by the next block; the final
			 * null terminator is set explicitly below.
			 */
			print_count = narrow_string_snprintf(
			              (char *) &( recovery_password[ block_index * 7 ] ),
			              8,
			              "%06" PRIu32 "-",
			              formatted_block );
		}
		else
		{
			/* Last block: "XXXXXX" (6 chars) + null = 7 bytes, fits exactly. */
			print_count = narrow_string_snprintf(
			              (char *) &( recovery_password[ block_index * 7 ] ),
			              7,
			              "%06" PRIu32,
			              formatted_block );
		}
		/* For blocks 0-6 the format writes 7 characters ("XXXXXX-");
		 * for block 7 it writes 6 characters ("XXXXXX").
		 * Treat print_count > 7 as overflow (never expected).
		 */
		if( ( print_count < 0 )
		 || ( (size_t) print_count > 7 ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to set recovery password block: %d.",
			 function,
			 block_index );

			goto on_error;
		}
	}
	recovery_password[ 55 ] = 0;

	memory_set(
	 unencrypted_data,
	 0,
	 unencrypted_data_size );

	memory_free(
	 unencrypted_data );

	return( 1 );

on_error:
	if( aes_context != NULL )
	{
		libcaes_context_free(
		 &aes_context,
		 NULL );
	}
	if( unencrypted_data != NULL )
	{
		memory_set(
		 unencrypted_data,
		 0,
		 unencrypted_data_size );

		memory_free(
		 unencrypted_data );
	}
	return( -1 );
}
