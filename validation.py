from openai import OpenAI
client = OpenAI(api_key='sk-proj-RIX1rQUybCRcFwodkJDQT3BlbkFJykm22GNqPzMEjshsnQ2q')

# file=client.files.create(
#   file=open("training_data.jsonl", "rb"),
#   purpose="fine-tune"
# )

client.fine_tuning.jobs.create(
  training_file="file-U0VCoqfIPGGb3KQtekaWH3dI", 
  model="gpt-3.5-turbo"
)
# print(client.fine_tuning.jobs.retrieve("file-U0VCoqfIPGGb3KQtekaWH3dI"))