import { Suspense } from "react";
import { AssessmentTabs } from "@/components/assessment/AssessmentTabs";

export default async function AssessmentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <Suspense>
      <AssessmentTabs id={id} />
    </Suspense>
  );
}
