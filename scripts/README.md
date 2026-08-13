# Nsight scheduler report

`nsys_scheduler_report.py` summarizes CUDA kernel activity on the explicit streams owned by the chip scheduler.

Export an Nsight Systems capture to SQLite, then pass the report and the stream IDs printed by the scheduler:

```bash
nsys export --type sqlite --output scheduler.sqlite scheduler.nsys-rep
scripts/nsys_scheduler_report.py scheduler.sqlite 17 18
```

The helper reports each stream's kernel count and summed kernel duration. Across all selected streams, it reports the interval from the first kernel start to the last kernel end, the union of intervals with at least one active kernel, the time with at least two simultaneous kernels, overlap as a percentage of the wall interval, and the maximum number of simultaneous kernels.

Stream IDs must be unique. The script opens the report read-only and exits with an error if the Nsight kernel table is missing or none of the requested streams contain kernels.
