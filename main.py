import asyncio
from agents.monitoring import MonitoringAgent
from agents.detection import DetectionAgent
from agents.coordinator import CoordinatorAgent
from agents.decision import DecisionAgent
from agents.response import ResponseAgent
from agents.feedback import FeedbackAgent
from agents.filter import FilterAgent
from agents.normalizer import NormalizerAgent
from models.anomaly import AnomalyModel

async def pipeline(event, detection, coordinator, decision_agent, response, feedback, filter_agent, normalizer):
    event = normalizer.normalize(event)
    if not event or not filter_agent.is_relevant(event):
        return
    print(f"[LOG] {event}")
    threat = detection.detect(event)
    coordinated = coordinator.process(threat)
    decision = decision_agent.decide(coordinated)
    response.execute(decision)
    feedback.update(decision)

async def main():
    model = AnomalyModel()
    monitoring = MonitoringAgent()
    detection = DetectionAgent()
    coordinator = CoordinatorAgent()
    decision_agent = DecisionAgent()
    response = ResponseAgent()
    feedback = FeedbackAgent(anomaly_model=model)
    filter_agent = FilterAgent()
    normalizer = NormalizerAgent()

    queue = asyncio.Queue()

    async def producer():
        while True:
            event = await asyncio.to_thread(monitoring.get_event)
            await queue.put(event)

    async def consumer():
        while True:
            event = await queue.get()
            await pipeline(event, detection, coordinator, decision_agent, response, feedback, filter_agent, normalizer)
            queue.task_done()

    await asyncio.gather(producer(), consumer())

if __name__ == "__main__":
    asyncio.run(main())
