[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
To enable users to efficiently prioritize suspicious endpoints and investigate, **RSA Netwitness
Endpoint** provides a scoring mechanism based on the behavior that was seen. Each endpoint will have
an aggregated suspect score, which is calculated based on the suspect scores of all modules found on
that endpoint. The suspect scores are calculated based on the IOCs that are triggered on the
endpoint.  
  
There are different levels of IOCs based on how suspicious the behavior is considered. IOCs have
four possible levels, ranging from 0 to 3. Below are the details of each IOC level:  
  

|           |          |                                             |                 |
|-----------|----------|---------------------------------------------|-----------------|
| IOC Level | Severity | Description                                 | IOC Score Range |
| 0         | Critical | Confirmed infection                         | 1024-1024       |
| 1         | High     | Highly suspicious activity                  | 128-1023        |
| 2         | Medium   | Activity might be suspicious                | 8-127           |
| 3         | Low      | More informational, but could be suspicious | 1-7             |
