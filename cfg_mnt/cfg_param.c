#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_param.h"
#include "cfg_capability.h"

/* for led control capability */
led_capability_s led_ctrl_capability_list[] = {
	{ CENTRAL_LED,		SUBFT_CENTRAL_LED},
	{ LP55XX_LED, 		SUBFT_LP55XX_LED},
	{ LED_ON_OFF, 		SUBFT_CTRL_LED},
	{ LED_BRIGHTNESS, 	SUBFT_CTRL_LED},
	{ LED_AURA,		SUBFT_AURARGB},

	/* END */
	{ 0, 0 }
};

/*
========================================================================
Routine Description:
	Index to name for subfeature.

Arguments:
	ftIndex		- Index

Return Value:
	subfeature name

========================================================================
*/
char *cm_subfeatureIndex2Name(int ftIndex)
{
	struct subfeature_mapping_s *pFeature = NULL;
	char *ftName = NULL;

	for (pFeature = &subfeature_mapping_list[0]; pFeature->index != 0; pFeature++) {
		if (ftIndex == pFeature->index) {
			ftName = pFeature->name;
			break;
		}
	}

	return ftName;
} /* End of cm_subfeatureIndex2Name */

/*
========================================================================
Routine Description:
	Add dynamic private feature for reporting.

Arguments:
	ftArray		- feature attary
	supportedBandNum		- supported band number
	supportedRole		- supported role

Return Value:
	None

========================================================================
*/
void cm_addDynamicPrivateFeature(json_object *ftArray, int supportedBandNum, int supportedRole)
{
	char *ftName = NULL;
	int ledCtrlVal = nvram_get_int("led_ctrl_cap");
	led_capability_s *pCapability = NULL;
	int i = 0, radioFt[] = { SUBFT_RADIO_BAND1, SUBFT_RADIO_BAND2, SUBFT_RADIO_BAND3, SUBFT_RADIO_BAND4, 0};
#ifdef RTCONFIG_AMAS_CHANNEL_PLAN
	int channelSetFt[] = { SUBFT_CHANNEL_SET_BAND1, SUBFT_CHANNEL_SET_BAND2, SUBFT_CHANNEL_SET_BAND3, SUBFT_CHANNEL_SET_BAND4, 0};
#endif

	if (ftArray == NULL) {
		DBG_ERR("ftArray is NULL");
		return;
	}

	/* for all supported role */
	/* for led control */
	if (ledCtrlVal > 0) {
		for (pCapability = &led_ctrl_capability_list[0]; pCapability->type != 0; pCapability++) {
			if ((ledCtrlVal & pCapability->type) > 0) {
				if ((ftName = cm_subfeatureIndex2Name(pCapability->subtype)))
					json_object_array_add(ftArray, json_object_new_string(ftName));
			}
		}
	}

#ifdef RTCONFIG_AMAS_CHANNEL_PLAN
	/* for channel plan */
	if ((ftName = cm_subfeatureIndex2Name(SUBFT_CHANNEL_PLAN)))
		json_object_array_add(ftArray, json_object_new_string(ftName));
#endif

	/* for RE supported role */
	if (supportedRole == RE_SUPPORT) {
		/* for wifi radio */
		for (i = 0; i < supportedBandNum; i++) {
			if (radioFt[i] == 0) {
				DBG_INFO("radioFt[%d] is 0, band num(%d)", i, supportedBandNum);
				break;
			}

			if ((ftName = cm_subfeatureIndex2Name(radioFt[i])))
				json_object_array_add(ftArray, json_object_new_string(ftName));
		}

#ifdef RTCONFIG_AMAS_CHANNEL_PLAN
		/* wifi channel set */
		for (i = 0; i < supportedBandNum; i++) {
			if (channelSetFt[i] == 0) {
				DBG_INFO("channelSetFt[%d] is 0, band num(%d)", i, supportedBandNum);
				break;
			}

			if ((ftName = cm_subfeatureIndex2Name(channelSetFt[i])))
				json_object_array_add(ftArray, json_object_new_string(ftName));
		}
#endif
	}
} /* End of cm_addDynamicPrivateFeature */
