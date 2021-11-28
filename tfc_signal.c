/*
 * tfcrypt -- high security Threefish encryption tool.
 *
 * tfcrypt is copyrighted:
 * Copyright (C) 2012-2019 Andrey Rys. All rights reserved.
 *
 * tfcrypt is licensed to you under the terms of std. MIT/X11 license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "tfcrypt.h"

void exit_sigterm(int signal)
{
	xexit(0);
}

void handle_sigtstp(int signal)
{
	if (signal == SIGTSTP) {
		tfc_useconds freeze_start, freeze_end;

		tfc_getcurtime(&freeze_start);
		kill(getpid(), SIGSTOP);
		tfc_getcurtime(&freeze_end);
		total_time -= (freeze_end - freeze_start);
	}
}

void print_crypt_status(int signal)
{
	tfc_fsize wr_speed;
	double seconds, human_totalproc_src, human_totalproc_dst, human_totalwrit_dst, human_wr_speed;
	int src_scale_idx, dst_scale_idx, wri_scale_idx, wr_speed_scale;
	const char *oper_mode, *inplace;
	static tfc_yesno last;

	if (last == YES) return;
	if (signal == 0 || signal == -1) last = YES;

	switch (do_edcrypt) {
		case TFC_DO_ENCRYPT: oper_mode = "encrypted"; break;
		case TFC_DO_DECRYPT: oper_mode = "decrypted"; break;
		default:
			if (ctr_mode == TFC_MODE_PLAIN) oper_mode = "written";
			else if (ctr_mode == TFC_MODE_SKSUM) oper_mode = "hashed";
			else oper_mode = NULL;
			break;
	}

	if (signal == SIGINT || signal == SIGTERM) {
		do_stop = YES;
	}

	tfc_getcurtime(&current_time);
	total_time += (current_time - delta_time);
	seconds = TFC_UTODSECS(current_time - delta_time);
	wr_speed = delta_processed / seconds;
	tfc_describescale(total_processed_src, &human_totalproc_src, &src_scale_idx);
	tfc_describescale(total_processed_dst, &human_totalproc_dst, &dst_scale_idx);
	tfc_describescale(total_written_dst, &human_totalwrit_dst, &wri_scale_idx);
	tfc_describescale(wr_speed, &human_wr_speed, &wr_speed_scale);

	if (bench_timer) {
		tfc_say("done!");
		tfc_say("%s %s benchmark results:", tfc_format_pid(progname), tfc_modename(ctr_mode));
		tfc_nfsay(stdout, "%s %llu (%.2f%s) bytes, "
			"avg. speed %llu (%.2f%s) B/s, time %.4fs.",
			oper_mode,
			total_processed_src, human_totalproc_src, tfc_getscale(src_scale_idx),
			wr_speed, human_wr_speed, tfc_getscale(wr_speed_scale), seconds);
		tfc_esay("\n");
		xexit(0);
	}

	if (do_statline_dynamic == YES) inplace = "\033[2K\r";
	else inplace = "";

	if (do_less_stats == YES) {
		tfc_nfsay(stderr, "%s%s%s:"
			" %s %.2f%s,"
			" %.2f%s B/s @%s",
			inplace, (last && show_when_done) ? "finished: " : "", tfc_format_pid(progname),
			oper_mode,
			human_totalproc_dst, tfc_getscale(dst_scale_idx),
			human_wr_speed, tfc_getscale(wr_speed_scale), tfc_format_time(total_time));
	}
	else {
		if (ctr_mode <= TFC_MODE_PLAIN) tfc_nfsay(stderr, "%s%s%s: read: %llu (%.2f%s),"
			" %s %llu (%.2f%s) bytes,"
			" (%llu (%.2f%s) B/s), time %s",
			inplace, (last && show_when_done) ? "finished: " : "", tfc_format_pid(progname),
			total_processed_src, human_totalproc_src, tfc_getscale(src_scale_idx),
			oper_mode,
			total_processed_dst, human_totalproc_dst, tfc_getscale(dst_scale_idx),
			wr_speed, human_wr_speed, tfc_getscale(wr_speed_scale), tfc_format_time(total_time));
		else tfc_nfsay(stderr, "%s%s%s: read: %llu (%.2f%s),"
			" %s %s %llu (%.2f%s) bytes,"
			" written %llu (%.2f%s) bytes,"
			" (%llu (%.2f%s) B/s), time %s",
			inplace, (last && show_when_done) ? "finished: " : "", tfc_format_pid(progname),
			total_processed_src, human_totalproc_src, tfc_getscale(src_scale_idx),
			tfc_modename(ctr_mode), oper_mode,
			total_processed_dst, human_totalproc_dst, tfc_getscale(dst_scale_idx),
			total_written_dst, human_totalwrit_dst, tfc_getscale(wri_scale_idx),
			wr_speed, human_wr_speed, tfc_getscale(wr_speed_scale), tfc_format_time(total_time));
	}

	if (do_stop == NO && do_statline_dynamic == NO) tfc_esay("\n");
	if (last) tfc_esay("\n");
	statline_was_shown = YES;

	if ((signal == SIGINT || signal == SIGTERM) && do_stop == YES) {
		tfc_esay("\n");
		exit_sigterm(signal);
	}

	delta_processed = 0;
	tfc_getcurtime(&delta_time);

	handle_sigtstp(signal);

	if (status_timer) setup_next_alarm(status_timer);
}

void change_status_width(int signal)
{
	if (do_less_stats == YES) do_less_stats = NO;
	else if (do_less_stats == NO) do_less_stats = YES;
}

void change_status_timer(int signal)
{
	static tfc_useconds reset_timer;
	tfc_useconds t;

	tfc_getcurtime(&t);
	if (reset_timer && (t - reset_timer) < TFC_DTOUSECS(0.1)) status_timer = 0;
	reset_timer = t;

	if (status_timer == 0) status_timer = TFC_DTOUSECS(0.25);
	else status_timer *= 2;

	if (verbose) tfc_esay("%s: status timer was changed to %.2fs",
		tfc_format_pid(progname), TFC_UTODSECS(status_timer));
	setup_next_alarm(status_timer);
}

void setup_next_alarm(tfc_useconds useconds)
{
	struct itimerval it;

	memset(&it, 0, sizeof(struct itimerval));
	it.it_value.tv_sec = useconds / 1000000;
	it.it_value.tv_usec = useconds % 1000000;
	setitimer(ITIMER_REAL, &it, NULL);
}
