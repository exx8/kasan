// SPDX-License-Identifier: GPL-2.0

/*
 * Userspace notification interface for debugging tools.
 *
 * Provide two sysfs files:
 *  - /sys/kernel/error_report/last_report
 *  - /sys/kernel/error_report/report_count
 * that contain the last debugging tool report (taken from dmesg, delimited by
 * the error_report_start/error_report_end tracing events) and the total report
 * count.
 *
 * Because reporting code can be called from low-level routines (e.g. locking
 * primitives or allocator guts), report recording is implemented using a
 * seqlock-alike lock-free algorithm.
 */

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/workqueue.h>
#include <trace/events/error_report.h>
#include <trace/events/printk.h>

static struct kobject *error_report_kobj;

#define BUF_SIZE PAGE_SIZE
/* Two buffers to store the finished report and the report being recorded. */
static char report_buffer[2][BUF_SIZE];
/*
 * Total report count. Also serves as a latch for report_buffer:
 * report_buffer[num_reports % 2] is the currently available report,
 * report_buffer[(num_reports + 1) % 2] is the report being recorded.
 */
static atomic_t num_reports;

/*
 * PID of the task currently recording the report, as returned by
 * get_encoded_pid(), or -1. Used as a writer lock for report_buffer.
 * A regular spinlock couldn't be used here, as probe_console() can be called
 * from any thread, and it needs to know whether that thread is holding the
 * lock.
 */
static atomic_t current_pid = ATOMIC_INIT(-1);

static size_t current_report_pos;
static bool truncated;
static const char TRUNC_MSG[] = "<truncated>\n";

static struct delayed_work reporting_done;

static void error_report_notify(struct work_struct *work)
{
	sysfs_notify(error_report_kobj, NULL, "last_report");
	sysfs_notify(error_report_kobj, NULL, "report_count");
}
static DECLARE_DELAYED_WORK(reporting_done, error_report_notify);

/*
 * Return the current PID melted together with in_task(). This lets us
 * distinguish between normal task context and IRQ context.
 */
static int get_encoded_pid(void)
{
	return (current->pid << 1) | (!!in_task());
}

/*
 * Trace hook for the error_report_start event. In an unlikely case of another
 * task already printing a report bail out, otherwise save the current pid
 * together with in_task() return value.
 */
static void probe_report_start(void *ignore, const char *tool_name,
			       unsigned long id)
{
	/*
	 * Acquire the writer lock. Any racing probe_report_start will not
	 * record anything. Pairs with the release in probe_report_end().
	 */
	if (atomic_cmpxchg_acquire(&current_pid, -1, get_encoded_pid()) != -1)
		return;
	current_report_pos = 0;
}

/*
 * Trace hook for the error_report_end event. If an event from the mismatching
 * error_report_start is received, it is ignored. Otherwise, null-terminate the
 * buffer, increase the report count (effectively releasing the report to
 * last_report_show() and schedule a notification about a new report.
 */
static void probe_report_end(void *ignore, const char *tool_name,
			     unsigned long id)
{
	pid_t pid = atomic_read(&current_pid);
	int idx;

	if (pid != get_encoded_pid())
		return;

	idx = (atomic_read(&num_reports) + 1) % 2;
	if (current_report_pos == BUF_SIZE)
		report_buffer[idx][current_report_pos - 1] = 0;
	else
		report_buffer[idx][current_report_pos] = 0;

	/* Pairs with acquire in last_report_show(). */
	atomic_inc_return_release(&num_reports);
	schedule_delayed_work(&reporting_done, 0);
	/*
	 * Release the writer lock. Pairs with the acquire in
	 * probe_report_start().
	 */
	atomic_set_release(&current_pid, -1);
}

/*
 * Trace hook for the console event. If a line comes from a task/CPU that did
 * not send the error_report_start event, that line is ignored. Otherwise, it
 * is stored in the report_buffer[(num_reports + 1) % 2].
 */
static void probe_console(void *ignore, const char *buf, size_t len)
{
	int pid = atomic_read(&current_pid);
	size_t to_copy;
	int idx;

	if (pid != get_encoded_pid() || truncated)
		return;

	idx = (atomic_read(&num_reports) + 1) % 2;
	to_copy = min(len, BUF_SIZE - current_report_pos);
	memcpy(report_buffer[idx] + current_report_pos, buf, to_copy);
	current_report_pos += to_copy;
	if (len > to_copy) {
		truncated = true;
		memcpy(report_buffer[idx] + current_report_pos - sizeof(TRUNC_MSG),
		       TRUNC_MSG, sizeof(TRUNC_MSG));
	}
}

static void register_tracepoints(void)
{
	register_trace_console(probe_console, NULL);
	register_trace_error_report_start(probe_report_start, NULL);
	register_trace_error_report_end(probe_report_end, NULL);
}

/*
 * read() handler for /sys/kernel/error_report/last_report.
 * Because the number of reports can change under our feet, check it again
 * after copying the report, and retry if the numbers mismatch.
 * */
static ssize_t last_report_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	/* Pairs with release in probe_report_end(). */
	int index = atomic_read_acquire(&num_reports), old_index;
	ssize_t ret;

	do {
		old_index = index;
		/*
		 * If index and old_index mismatch, we might be accessing
		 * report_buffer concurrently with a writer thread. In that
		 * case the read data will be discarded.
		 */
		ret = data_race(strscpy(buf, report_buffer[index % 2], BUF_SIZE));
		/*
		 * Prevent reordering between the memcpy above and the atomic
		 * read below.
		 * See https://www.hpl.hp.com/techreports/2012/HPL-2012-68.pdf
		 * for more details.
		 */
		smp_rmb();
		/* Pairs with release in probe_report_end(). */
		index = atomic_read_acquire(&num_reports);
	} while (index != old_index);
	return ret;
}

/*
 * read() handler for /sys/kernel/error_report/report_count.
 */
static ssize_t report_count_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", atomic_read(&num_reports));
}

static struct kobj_attribute last_report_attr = __ATTR_RO(last_report);
static struct kobj_attribute report_count_attr = __ATTR_RO(report_count);
static struct attribute *error_report_sysfs_attrs[] = {
	&last_report_attr.attr,
	&report_count_attr.attr,
	NULL,
};

static const struct attribute_group error_report_sysfs_attr_group = {
	.attrs = error_report_sysfs_attrs,
};

/*
 * Set up report notification: register tracepoints and create
 * /sys/kernel/error_report/.
 */
static void error_report_notify_setup(void)
{
	int err;

	register_tracepoints();
	error_report_kobj = kobject_create_and_add("error_report", kernel_kobj);
	if (!error_report_kobj)
		goto error;
	err = sysfs_create_group(error_report_kobj,
				 &error_report_sysfs_attr_group);
	if (err)
		goto error;
	return;

error:
	if (error_report_kobj)
		kobject_del(error_report_kobj);
}
late_initcall(error_report_notify_setup);
