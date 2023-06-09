#ifndef __CFG_ROAMINGINFO_H__
#define __CFG_ROAMINGINFO_H__
#include "cfg_sched.h"

#define STA_ROAMING_FILE      "/tmp/sta_romaing.json"
#define STA_ROAMING_FILE_LOCK "sta_roaming"
#define STA_ROAMING_TIME      5 
#define CHECK_ROAMING_INFO_INTERVAL	STA_ROAMING_TIME
extern void cm_checkRoamingInfoEvent(struct sched *sched);
extern void cm_recordRoamingInfo(char *staMac);
extern void cm_registerRoamingInfoSch();

#endif /* __CFG_ROAMINGINFO_H__ */
/* End of cfg_roaminginfo.h */
