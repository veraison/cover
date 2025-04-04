package policy

realm contains ect if {
  ect = input[_]
  ect.environment.instance.type == "bytes"
}

refvals contains ect if {
  ect = realm[_]
  ect["cm-type"] == "reference-values"
}

evidence contains ect if {
  ect = realm[_]
  ect["cm-type"] == "evidence"
}

# If cryptographic verification completes (implicit in getting here), instance
# identity has been recognized.
instance_identity := RECOGNIZED_INSTANCE

rim_matched if {
  ref := refvals[_]["element-list"][_]["mval"]["integrity-registers"][`"rim"`]
  ev := evidence[_]["element-list"][_]["mval"]["integrity-registers"][`"rim"`]
  ref == ev
}

# TODO: figure out what this should look like (can't find an example of it
# being represented in a CoMID)
pv_matched := true

ref_rems contains rem if {
  rem := {
    "name": name,
    "value": refvals[_]["element-list"][_]["mval"]["integrity-registers"][name]["value"]
  }
  name != "rim"
}

ev_rems contains rem if {
  rem := {
    "name": name,
    "value": evidence[_]["element-list"][_]["mval"]["integrity-registers"][name]["value"]
  }
  name != "rim"
}

rems_matched if {
  every ev in ev_rems {
    ref = ref_rems[_]
    ref == ev
  }
}

executables := APPROVED_RT if {
  rim_matched
  pv_matched
  rems_matched
} else := APPROVED_BOOT if {
  rim_matched
  pv_matched
} else := UNRECOGNIZED_RT

# TODO: this needs to be taken from runtime_opaque from the platfrom appraisal
runtime_opaque := ENCRYPTED_RT
