#ifndef TELEMETRYINTERFACE_H
#define TELEMETRYINTERFACE_H

void t2Init(const char *component);
void t2Uninit(void);
void t2CountNotify(char *marker, int val);
void t2ValNotify(char *marker, char *val);

#endif
