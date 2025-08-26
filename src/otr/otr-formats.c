/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) - 2012  David Goulet <dgoulet@ev0ke.net>
 *                 2014  Alexander Færøy <ahf@0x90.dk>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <irssi/src/otr/otr.h>
#include <irssi/src/otr/otr-formats.h>

FORMAT_REC fe_otr_formats[] = {
	/* clang-format off */
	{ MODULE_NAME, "Core", 0 },

	/* Status bar format. */
	{ NULL, "OTR Statusbar", 0 },

	{ "otr_stb_plaintext", "{sb plaintext}", 0},
	{ "otr_stb_finished", "{sb %yfinished%n}", 0},
	{ "otr_stb_unknown", "{sb {hilight state unknown (BUG!)}}", 0},
	{ "otr_stb_untrusted", "{sb %GOTR%n (%runverified%n)}", 0},
	{ "otr_stb_trust", "{sb %GOTR%n}", 0},

	/* OTR format. */
	{ NULL, "OTR", 0 },

	{ "otr_auth_aborted", "Authentication aborted", 0},
	{ "otr_auth_initiated", "Initiated authentication", 0},
	{ "otr_auth_ongoing_aborted", "Ongoing authentication aborted", 0},
	{ "otr_auth_response", "Responding to authentication", 0},

	{ "otr_ctx_list_header", "{hilight Contexts}", 0},
	{ "otr_ctx_list_encrypted_line", "{hilight $0} - {hilight $1} (Encrypted)", 2, { 0, 0 }},
	{ "otr_ctx_list_finished_line", "{hilight $0} - {hilight $1} (Finished)", 2, { 0, 0 }},
	{ "otr_ctx_list_manual_line", "  {hilight $0} (Manual)", 1, { 0, 0 }},
	{ "otr_ctx_list_plaintext_line", "{hilight $0} - {hilight $1} (Plaintext)", 2, { 0, 0 }},
	{ "otr_ctx_list_smp_line", "  {hilight $0} (SMP)", 1, { 0, 0 }},
	{ "otr_ctx_list_unknown_line", "{hilight $0} - {hilight $1} (Unknown)", 2, { 0, 0 }},
	{ "otr_ctx_list_unused_line", "{hilight $0} - {hilight $1} (Unused)", 2, { 0, 0 }},
	{ "otr_ctx_list_unverified_line", "  {hilight $0} (Unverified)", 1, { 0, 0 }},
	{ "otr_ctx_list_footer", "", 0},
	{ "otr_ctx_missing", "{error No active OTR contexts found}", 0},
	{ "otr_ctx_nick_missing", "{error Context for {hilight $0} not found}", 1, { 1 }},

	{ "otr_fp_already_distrusted", "{error Already distrusting: {hilight $0}", 1, { 0 }},
	{ "otr_fp_already_trusted", "{error Already trusting: {hilight $0}", 1, { 0 }},
	{ "otr_fp_ctx_encrypted", "Fingerprint context is still encrypted. Finish the OTR session before forgetting a fingerprint", 0},
	{ "otr_fp_distrusted", "Distrusting {hilight $0}", 1, { 0 }},
	{ "otr_fp_forgotten", "Fingerprint {hilight $0} forgotten", 1, { 0 }},
	{ "otr_fp_info", "OTR key fingerprint: {hilight $1} for {hilight $0}", 2, { 0, 0 }},
	{ "otr_fp_missing", "{error Fingerprint {hilight $0} not found", 1, { 0 }},
	{ "otr_fp_nick", "Fingerprint for {hilight $0}: {hilight $1}", 2, { 0, 0 }},
	{ "otr_fp_trusted", "Trusting {hilight $0}", 1, { 0 }},

	{ "otr_keygen_completed", "OTR key generation for {hilight $0} completed", 1, { 0 }},
	{ "otr_keygen_failed", "OTR key generation for {hilight $0} failed: {error $1}", 2, { 0, 0 }},
	{ "otr_keygen_running", "OTR key generation for {hilight $0} is still in progress", 1, { 0 }},
	{ "otr_keygen_started", "OTR key generation for {hilight $0} started", 1, { 0 }},

	{ "otr_keys_unavailable", "{error No OTR keys available}", 0},

	{ "otr_msg_encryption_ended", "{hilight $0} has closed the connection to you", 1, { 0 }},
	{ "otr_msg_encryption_error", "{error An error occurred when encrypting your message}", 0},
	{ "otr_msg_encryption_required", "Encryptioned is required", 0},
	{ "otr_msg_error", "Error in private conversation: {error $0}", 1, { 0 }},
	{ "otr_msg_general_error", "General Error: {error $0}", 1, { 0 }},
	{ "otr_msg_malformed", "Malformed message from {hilight $0}", 1, { 0 }},
	{ "otr_msg_not_in_private", "The encrypted message from {hilight $0} was unreadable because you're not communicating privately", 1, { 0 }},
	{ "otr_msg_reflected", "Received reflected message from {hilight $0}", 0, { 0 }},
	{ "otr_msg_resent", "The last message to {hilight $0} was resent: $1", 2, { 0, 0 }},
	{ "otr_msg_unencrypted", "The following message from {hilight $0} was {error not} encrypted", 1, { 0 }},
	{ "otr_msg_unreadable", "Unreadable encrypted message from {hilight $0}", 1, { 0 }},
	{ "otr_msg_unrecognized", "Unrecognized OTR message from {hilight $0}", 1, { 0 }},

	{ "otr_session_already_finished", "Nothing to do", 0},
	{ "otr_session_already_secured", "Secure session with {hilight $0} already established", 1, { 0 }},
	{ "otr_session_finished", "{hilight $0} has finished the OTR session. Use /otr init to restart or /otr finish to finish.", 1, { 0 }},
	{ "otr_session_finishing", "Finished conversation with {hilight $0}", 1, { 0 }},
	{ "otr_session_initiating", "Initiating OTR session ...", 0},
	{ "otr_session_insecure", "Session insecured", 0},
	{ "otr_session_missing", "{error No OTR session available}", 0},
	{ "otr_session_secure", "Session secured", 0},
	{ "otr_session_unauthenticated_warning", "Your peer is not authenticated", 0},

	{ "otr_smp_answer_footer", "Use /otr auth <answer> to complete", 0},
	{ "otr_smp_answer_header", "{hilight $0} wants to authenticate and asked:", 1, { 0 }},
	{ "otr_smp_answer_question", "Question: {hilight $0}", 1, { 0 }},
	{ "otr_smp_failure", "Authentication with {hilight $0} failed", 1, { 0 }},
	{ "otr_smp_in_progress", "{hilight $0} replied to your auth request", 1, { 0 }},
	{ "otr_smp_secret_question", "{hilight $0} wants to authenticate. Use /otr auth <secret> to complete", 1, { 0 }},
	{ "otr_smp_success", "Authentication with {hilight $0} successful", 1, { 0 }},

	/* Last element. */
	{ NULL, NULL, 0 }
	/* clang-format on */
};
